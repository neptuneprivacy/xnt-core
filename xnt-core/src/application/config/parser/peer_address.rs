//! Peer addresses given on the command line, and which network stack dials
//! them.
//!
//! The syntax of an address decides the stack, with the default libp2p ports
//! as the exception:
//!
//! | Input                                            | Stack                         |
//! |--------------------------------------------------|-------------------------------|
//! | `ip:port`, port other than 9901 and 9902         | legacy                        |
//! | `ip:9902`                                        | libp2p, `/tcp/9902`           |
//! | `ip:9901`                                        | libp2p, `/udp/9901/quic-v1`   |
//! | multiaddress with `/quic-v1` or `/p2p`           | libp2p                        |
//! | `/ip4/<ip>/tcp/9898` (or `/ip6/...`)             | legacy                        |
//! | other multiaddress with `/tcp/<port>`            | libp2p                        |
//! | bare IP, or a multiaddress naming only an IP     | both, on the default ports    |
//!
//! The ports compared against are the compile-time defaults, not the ports
//! this node is configured to listen on, so that the classification of an
//! address does not depend on the local configuration.
//!
//! Multiaddresses that name a host by DNS name (`/dns`, `/dns4`, `/dns6`, or
//! `/dnsaddr`) are refused, because the DNS transport of libp2p is not
//! compiled in.

use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

use multiaddr::Multiaddr;
use multiaddr::Protocol;

use super::multiaddr::direct_socket_addr;
use super::multiaddr::is_relayed;
use super::multiaddr::refuse_dns;
use super::multiaddr::socketaddr_to_multiaddr;
use super::multiaddr::socketaddr_to_quic_multiaddr;

/// Default port of the legacy TCP peer stack.
pub const DEFAULT_PEER_PORT: u16 = 9898;

/// Default port of the libp2p QUIC transport (UDP).
pub const DEFAULT_QUIC_PORT: u16 = 9901;

/// Default port of the libp2p TCP transport.
pub const DEFAULT_LIBP2P_TCP_PORT: u16 = 9902;

/// A peer address as given with `--peer`, in one of three accepted forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAddress {
    /// `ip:port`, e.g. `1.2.3.4:9898` or `[::1]:9898`.
    Socket(SocketAddr),

    /// A bare IP address, e.g. `1.2.3.4`.
    Ip(IpAddr),

    /// A multiaddress, e.g. `/ip4/1.2.3.4/udp/9901/quic-v1`.
    Multiaddr(Multiaddr),
}

impl PeerAddress {
    /// The address at which the legacy TCP stack dials this peer, if that stack
    /// dials it at all.
    pub fn legacy_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket(socket_addr) => {
                (!is_default_libp2p_port(socket_addr.port())).then_some(*socket_addr)
            }
            Self::Ip(ip) => Some(SocketAddr::new(*ip, DEFAULT_PEER_PORT)),
            Self::Multiaddr(multiaddr) => {
                if let Some(ip) = bare_ip(multiaddr) {
                    return Some(SocketAddr::new(ip, DEFAULT_PEER_PORT));
                }

                legacy_tcp_socket_addr(multiaddr)
            }
        }
    }

    /// The address at which the libp2p stack dials this peer, if that stack
    /// dials it at all.
    pub fn libp2p_address(&self) -> Option<Multiaddr> {
        match self {
            Self::Socket(socket_addr) => match socket_addr.port() {
                DEFAULT_QUIC_PORT => Some(socketaddr_to_quic_multiaddr(*socket_addr)),
                DEFAULT_LIBP2P_TCP_PORT => Some(socketaddr_to_multiaddr(*socket_addr)),
                _ => None,
            },
            Self::Ip(ip) => Some(default_quic_multiaddr(*ip)),
            Self::Multiaddr(multiaddr) => {
                if let Some(ip) = bare_ip(multiaddr) {
                    return Some(default_quic_multiaddr(ip));
                }

                legacy_tcp_socket_addr(multiaddr)
                    .is_none()
                    .then(|| multiaddr.clone())
            }
        }
    }

    /// The IP address of the peer itself, if the address names one.
    ///
    /// Relayed multiaddresses name the relay, so they yield `None`.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket(socket_addr) => Some(socket_addr.ip()),
            Self::Ip(ip) => Some(*ip),
            Self::Multiaddr(multiaddr) => {
                if is_relayed(multiaddr) {
                    return None;
                }

                multiaddr.iter().next().and_then(|protocol| match protocol {
                    Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                    Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                    _ => None,
                })
            }
        }
    }
}

impl From<SocketAddr> for PeerAddress {
    fn from(socket_addr: SocketAddr) -> Self {
        Self::Socket(socket_addr)
    }
}

impl FromStr for PeerAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(Self::Socket(socket_addr));
        }

        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }

        let multiaddr = s.parse::<Multiaddr>().map_err(|e| {
            format!("`{s}` is not `ip:port`, an IP address, or a multiaddress: {e}")
        })?;
        if multiaddr.is_empty() {
            return Err("peer address is empty".to_string());
        }
        refuse_dns(&multiaddr)?;

        Ok(Self::Multiaddr(multiaddr))
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(socket_addr) => write!(f, "{socket_addr}"),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Multiaddr(multiaddr) => write!(f, "{multiaddr}"),
        }
    }
}

fn is_default_libp2p_port(port: u16) -> bool {
    port == DEFAULT_QUIC_PORT || port == DEFAULT_LIBP2P_TCP_PORT
}

fn default_quic_multiaddr(ip: IpAddr) -> Multiaddr {
    socketaddr_to_quic_multiaddr(SocketAddr::new(ip, DEFAULT_QUIC_PORT))
}

/// The IP address of a multiaddress that consists of an IP address only.
fn bare_ip(multiaddr: &Multiaddr) -> Option<IpAddr> {
    let mut protocols = multiaddr.iter();
    let ip = match protocols.next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };

    protocols.next().is_none().then_some(ip)
}

/// The socket address of a multiaddress that consists of exactly an IP
/// address and TCP port [`DEFAULT_PEER_PORT`], the address of a legacy peer.
fn legacy_tcp_socket_addr(multiaddr: &Multiaddr) -> Option<SocketAddr> {
    let is_ip_and_tcp_port = multiaddr.iter().count() == 2
        && multiaddr
            .iter()
            .nth(1)
            .is_some_and(|protocol| protocol == Protocol::Tcp(DEFAULT_PEER_PORT));
    if !is_ip_and_tcp_port {
        return None;
    }

    direct_socket_addr(multiaddr)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const PEER_ID: &str = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

    fn parse(s: &str) -> PeerAddress {
        s.parse().unwrap()
    }

    fn socket(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn multiaddr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn each_syntax_parses_into_its_own_variant() {
        assert_eq!(
            PeerAddress::Socket(socket("1.2.3.4:9898")),
            parse("1.2.3.4:9898")
        );
        assert_eq!(
            PeerAddress::Socket(socket("[2001:db8::1]:9898")),
            parse("[2001:db8::1]:9898")
        );
        assert_eq!(
            PeerAddress::Ip("1.2.3.4".parse().unwrap()),
            parse("1.2.3.4")
        );
        assert_eq!(
            PeerAddress::Ip("2001:db8::1".parse().unwrap()),
            parse("2001:db8::1")
        );
        assert_eq!(
            PeerAddress::Multiaddr(multiaddr("/ip4/1.2.3.4/udp/9901/quic-v1")),
            parse("/ip4/1.2.3.4/udp/9901/quic-v1")
        );
    }

    #[test]
    fn invalid_input_is_refused() {
        for s in [
            "",
            "1.2.3.4:",
            "1.2.3.4:99999",
            "example.com:9898",
            "/ip4/1.2.3",
        ] {
            assert!(s.parse::<PeerAddress>().is_err(), "{s}");
        }
    }

    #[test]
    fn socket_addresses_on_other_ports_are_legacy() {
        for s in ["1.2.3.4:9898", "127.0.0.1:29790", "[::1]:40123"] {
            let peer = parse(s);
            assert_eq!(Some(socket(s)), peer.legacy_address(), "{s}");
            assert_eq!(None, peer.libp2p_address(), "{s}");
        }
    }

    #[test]
    fn socket_addresses_on_default_libp2p_ports_are_libp2p() {
        let tcp = parse("1.2.3.4:9902");
        assert_eq!(None, tcp.legacy_address());
        assert_eq!(
            Some(multiaddr("/ip4/1.2.3.4/tcp/9902")),
            tcp.libp2p_address()
        );

        let quic = parse("[2001:db8::1]:9901");
        assert_eq!(None, quic.legacy_address());
        assert_eq!(
            Some(multiaddr("/ip6/2001:db8::1/udp/9901/quic-v1")),
            quic.libp2p_address()
        );
    }

    #[test]
    fn multiaddresses_with_libp2p_protocols_are_libp2p() {
        for s in [
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            "/ip4/1.2.3.4/udp/40123/quic-v1",
            &format!("/ip4/1.2.3.4/tcp/9898/p2p/{PEER_ID}"),
            &format!("/p2p/{PEER_ID}"),
        ] {
            let peer = parse(s);
            assert_eq!(None, peer.legacy_address(), "{s}");
            assert_eq!(Some(multiaddr(s)), peer.libp2p_address(), "{s}");
        }
    }

    #[test]
    fn multiaddresses_with_dns_names_are_refused() {
        for s in [
            "/dns4/example.com/tcp/9898",
            "/dns6/example.com/tcp/9902",
            "/dns/example.com/udp/9901/quic-v1",
            &format!("/dnsaddr/example.com/p2p/{PEER_ID}"),
        ] {
            let error = s.parse::<PeerAddress>().unwrap_err();
            assert!(error.contains("DNS"), "{s}: {error}");
        }
    }

    #[test]
    fn tcp_multiaddress_on_legacy_port_is_legacy() {
        for (s, legacy_address) in [
            ("/ip4/1.2.3.4/tcp/9898", "1.2.3.4:9898"),
            ("/ip6/::1/tcp/9898", "[::1]:9898"),
        ] {
            let peer = parse(s);
            assert_eq!(Some(socket(legacy_address)), peer.legacy_address(), "{s}");
            assert_eq!(None, peer.libp2p_address(), "{s}");
        }
    }

    #[test]
    fn tcp_multiaddress_on_other_port_is_libp2p() {
        for s in ["/ip4/127.0.0.1/tcp/40123", "/ip4/1.2.3.4/tcp/9902"] {
            let peer = parse(s);
            assert_eq!(None, peer.legacy_address(), "{s}");
            assert_eq!(Some(multiaddr(s)), peer.libp2p_address(), "{s}");
        }
    }

    #[test]
    fn bare_ip_is_dialed_by_both_stacks() {
        for s in ["1.2.3.4", "/ip4/1.2.3.4"] {
            let peer = parse(s);
            assert_eq!(Some(socket("1.2.3.4:9898")), peer.legacy_address(), "{s}");
            assert_eq!(
                Some(multiaddr("/ip4/1.2.3.4/udp/9901/quic-v1")),
                peer.libp2p_address(),
                "{s}"
            );
        }

        let peer = parse("2001:db8::1");
        assert_eq!(Some(socket("[2001:db8::1]:9898")), peer.legacy_address());
        assert_eq!(
            Some(multiaddr("/ip6/2001:db8::1/udp/9901/quic-v1")),
            peer.libp2p_address()
        );
    }

    #[test]
    fn every_address_is_dialed_by_at_least_one_stack() {
        for s in [
            "1.2.3.4:9898",
            "1.2.3.4:9901",
            "1.2.3.4:9902",
            "1.2.3.4",
            "/ip4/1.2.3.4",
            "/ip4/1.2.3.4/tcp/9898",
            "/ip4/1.2.3.4/tcp/9898/tls",
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            &format!("/p2p/{PEER_ID}"),
        ] {
            let peer = parse(s);
            assert!(
                peer.legacy_address().is_some() || peer.libp2p_address().is_some(),
                "{s}"
            );
        }
    }

    #[test]
    fn ip_is_that_of_the_peer() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for s in [
            "1.2.3.4:9898",
            "1.2.3.4",
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            &format!("/ip4/1.2.3.4/tcp/9902/p2p/{PEER_ID}"),
        ] {
            assert_eq!(Some(ip), parse(s).ip(), "{s}");
        }

        for s in [
            &format!("/p2p/{PEER_ID}"),
            &format!("/ip4/1.2.3.4/tcp/9902/p2p/{PEER_ID}/p2p-circuit/p2p/{PEER_ID}"),
        ] {
            assert_eq!(None, parse(s).ip(), "{s}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "1.2.3.4:9898",
            "[2001:db8::1]:9898",
            "1.2.3.4",
            "/ip4/1.2.3.4/udp/9901/quic-v1",
        ] {
            assert_eq!(s, parse(s).to_string());
            assert_eq!(parse(s), parse(&parse(s).to_string()));
        }
    }
}
