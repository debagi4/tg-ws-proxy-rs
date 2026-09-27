//! A Telegram-only SOCKS5 entrance to the existing MTProto/WSS bridge.
//!
//! SOCKS carries the destination separately from MTProto. Unlike MTProxy,
//! ordinary clients do not hash their obfuscation key with a proxy secret;
//! un-obfuscated transports do not carry a DC at all. Resolve the destination
//! using an explicit DC map, then normalize either transport for the shared
//! upstream ladder. Never silently send an unknown destination over raw TCP.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::Config;
use crate::crypto::{
    ProtoTag, apply_keystream, build_raw_ciphers, generate_relay_init, make_cipher,
};
use crate::pool::WsPool;
use crate::proxy::{BridgeCiphers, ClientCipher, InboundTransport, serve_socks_transport};
use crate::runtime::Runtime;

#[derive(Clone, Debug)]
pub struct DcMapping {
    pub dc: i16,
    pub ip: IpAddr,
}

pub fn parse_dc_mapping(value: &str) -> Result<DcMapping, String> {
    let (dc, ip) = value.split_once(':').ok_or("expected signed DC:IP")?;
    let dc: i16 = dc.parse().map_err(|_| "invalid DC")?;
    if !matches!(dc.unsigned_abs(), 1..=5 | 203) {
        return Err("DC must be 1..5 or 203; use a negative value for media".into());
    }
    let ip = ip.parse().map_err(|_| "expected an IPv4 or IPv6 address")?;
    Ok(DcMapping { dc, ip })
}

// Reference for common IPv4 DC/media endpoints:
// https://github.com/AlexMelanFromRingo/tg-proxy/blob/main/src/ip_map.rs
// IPv6 entries are the production addresses built into both official clients
// (tdesktop mtproto_dc_options.cpp, Android tgnet ConnectionsManager.cpp);
// media IPv6 addresses only arrive via help.getConfig, so they are not here.
// Exact destination addresses, not whole Telegram subnets: a subnet may host
// multiple DCs. Unknown/new/CDN endpoints need an explicit --socks-dc mapping.
const DC_IPS: &[(i16, &str)] = &[
    (1, "149.154.175.50"),
    (1, "149.154.175.51"),
    (1, "149.154.175.53"),
    (1, "149.154.175.54"),
    (-1, "149.154.175.52"),
    (2, "149.154.167.41"),
    (2, "149.154.167.50"),
    (2, "149.154.167.51"),
    (2, "149.154.167.220"),
    (2, "95.161.76.100"),
    (-2, "149.154.167.151"),
    (-2, "149.154.167.222"),
    (-2, "149.154.167.223"),
    (-2, "149.154.162.123"),
    (3, "149.154.175.100"),
    (3, "149.154.175.101"),
    (-3, "149.154.175.102"),
    (4, "149.154.167.91"),
    (4, "149.154.167.92"),
    (-4, "149.154.164.250"),
    (-4, "149.154.166.120"),
    (-4, "149.154.166.121"),
    (-4, "149.154.167.118"),
    (-4, "149.154.165.111"),
    (5, "91.108.56.100"),
    (5, "91.108.56.101"),
    (5, "91.108.56.116"),
    (5, "91.108.56.126"),
    (5, "149.154.171.5"),
    (-5, "91.108.56.102"),
    (-5, "91.108.56.128"),
    (-5, "91.108.56.151"),
    (203, "91.105.192.100"),
    (1, "2001:b28:f23d:f001::a"),
    (2, "2001:67c:4e8:f002::a"),
    (3, "2001:b28:f23d:f003::a"),
    (4, "2001:67c:4e8:f004::a"),
    (5, "2001:b28:f23f:f005::a"),
];

static DC_MAP: LazyLock<Vec<DcMapping>> = LazyLock::new(|| {
    DC_IPS
        .iter()
        .map(|(dc, ip)| DcMapping {
            dc: *dc,
            ip: ip.parse().expect("built-in Telegram IP"),
        })
        .collect()
});

fn destination_dc(ip: IpAddr, config: &Config) -> Option<i16> {
    config
        .socks_dc
        .iter()
        .rev()
        .find(|m| m.ip == ip)
        .map(|m| m.dc)
        .or_else(|| {
            DC_MAP
                .iter()
                .find(|mapping| mapping.ip == ip)
                .map(|mapping| mapping.dc)
        })
}

/// Unknown destinations already reported at warn level. Telegram retries a
/// refused DC every few seconds, and one warning per attempt would flush a
/// router's small log ring. Bounded, so a client cycling through addresses
/// cannot grow it: an evicted address is merely reported again.
static REPORTED_UNKNOWN: Mutex<VecDeque<IpAddr>> = Mutex::new(VecDeque::new());
const REPORTED_UNKNOWN_CAP: usize = 64;

fn first_report(ip: IpAddr) -> bool {
    let mut reported = REPORTED_UNKNOWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if reported.contains(&ip) {
        return false;
    }
    if reported.len() == REPORTED_UNKNOWN_CAP {
        reported.pop_front();
    }
    reported.push_back(ip);
    true
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

async fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn negotiate(stream: &mut TcpStream, config: &Config) -> io::Result<i16> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(invalid("expected SOCKS5"));
    }
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(greeting[1])];
    stream.read_exact(methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        return Err(invalid("SOCKS5 no-auth method required"));
    }
    stream.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        reply(stream, 1).await?;
        return Err(invalid("invalid SOCKS5 request"));
    }
    if request[1] != 1 {
        reply(stream, 7).await?;
        return Err(invalid("only SOCKS5 CONNECT is supported (no UDP/BIND)"));
    }
    let ip: IpAddr = match request[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).into()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).into()
        }
        3 => {
            let len = usize::from(stream.read_u8().await?);
            let mut bytes = [0; 255];
            stream.read_exact(&mut bytes[..len]).await?;
            // Accept an IP encoded as DOMAIN, but do not resolve arbitrary
            // hostnames or mistake FakeIP for a Telegram DC destination.
            match std::str::from_utf8(&bytes[..len])
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(ip) => ip,
                None => {
                    reply(stream, 4).await?;
                    return Err(invalid("SOCKS destination must be a mapped Telegram IP"));
                }
            }
        }
        _ => {
            reply(stream, 8).await?;
            return Err(invalid("unsupported SOCKS address type"));
        }
    };
    let port = stream.read_u16().await?;
    if !matches!(port, 80 | 443 | 5222) {
        reply(stream, 2).await?;
        return Err(invalid("unsupported Telegram destination port"));
    }
    let Some(dc) = destination_dc(ip, config) else {
        if first_report(ip) {
            warn!(
                "SOCKS destination {}:{} has no DC mapping; configure --socks-dc \
                 (repeats for this address are logged at debug level)",
                ip, port
            );
        } else {
            debug!("SOCKS destination {}:{} has no DC mapping", ip, port);
        }
        reply(stream, 2).await?;
        return Err(invalid("unknown Telegram destination"));
    };
    // Telegram sends its transport header only after SOCKS CONNECT succeeds.
    // The WSS route is selected once that header reveals the framing protocol.
    reply(stream, 0).await?;
    Ok(dc)
}

async fn transport(
    stream: &mut TcpStream,
    label: SocketAddr,
    dc_idx: i16,
) -> io::Result<InboundTransport> {
    let mut header = [0; 64];
    stream.read_exact(&mut header[..1]).await?;
    // Ciphers are only created after the last read: anything alive across an
    // await is kept in every connection's state machine.
    let (proto, client_keys) = if header[0] == 0xef {
        (ProtoTag::Abridged, None)
    } else {
        stream.read_exact(&mut header[1..4]).await?;
        if let Some(proto) = ProtoTag::from_bytes(&header[..4]) {
            (proto, None)
        } else {
            stream.read_exact(&mut header[4..]).await?;
            let mut decrypted = header;
            apply_keystream(
                &mut make_cipher(&header[8..40], &header[40..56]),
                &mut decrypted,
            );
            let proto = ProtoTag::from_bytes(&decrypted[56..60]).ok_or_else(|| {
                invalid("unsupported MTProto transport (HTTP, Full and FakeTLS are not supported)")
            })?;
            // Without an MTProxy secret the header's DC bytes are not a
            // reliable routing source. The SOCKS destination is authoritative.
            (proto, Some(build_raw_ciphers(&header)))
        }
    };
    let relay_init = generate_relay_init(proto, dc_idx);
    let (tg_enc, tg_dec) = build_raw_ciphers(&relay_init);
    let (clt_dec, clt_enc) = match client_keys {
        Some((dec, enc)) => (ClientCipher(Some(dec)), ClientCipher(Some(enc))),
        None => (ClientCipher(None), ClientCipher(None)),
    };
    Ok(InboundTransport {
        label,
        dc_idx,
        proto,
        relay_init,
        ciphers: BridgeCiphers {
            clt_dec,
            clt_enc,
            tg_enc,
            tg_dec,
        },
    })
}

pub async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<WsPool>,
    runtime: Arc<Runtime>,
) {
    let _ = stream.set_nodelay(true);
    // Matched as a temporary, not bound: a named result would be kept for the
    // whole session, ciphers included, after `inbound` moves out of it.
    let inbound = match tokio::time::timeout(Duration::from_secs(config.handshake_timeout), async {
        let dc = negotiate(&mut stream, &config).await?;
        transport(&mut stream, peer, dc).await
    })
    .await
    {
        Ok(Ok(inbound)) => inbound,
        Ok(Err(error)) => {
            debug!("[{}] SOCKS handshake rejected: {}", peer, error);
            return;
        }
        Err(_) => {
            debug!("[{}] SOCKS handshake timeout", peer);
            return;
        }
    };
    serve_socks_transport(stream, config, pool, runtime, inbound).await;
}

#[cfg(test)]
mod tests;
