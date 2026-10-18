//! Conversions between multiaddresses, socket addresses, and IP addresses.

use std::net::IpAddr;
use std::net::SocketAddr;

use multiaddr::Multiaddr;
use multiaddr::Protocol;

/// Parse an IP address that is given either directly or as a multiaddress
/// naming it, e.g. `1.2.3.4` or `/ip4/1.2.3.4/udp/9901/quic-v1`.
///
/// Relayed multiaddresses name the relay rather than the peer, so they are
/// refused, as are multiaddresses without an IP address, and those that name a
/// host by DNS name; see [`refuse_dns`].
pub(crate) fn parse_ip_or_multiaddr(s: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip);
    }

    let multiaddr = s
        .parse::<Multiaddr>()
        .map_err(|e| format!("`{s}` is neither an IP address nor a multiaddress: {e}"))?;
    refuse_dns(&multiaddr)?;
    if is_relayed(&multiaddr) {
        return Err(format!(
            "multiaddress `{s}` names a relay rather than the peer"
        ));
    }

    ip_of(&multiaddr).ok_or_else(|| format!("multiaddress `{s}` does not name an IP address"))
}

/// Refuse a multiaddress that names a host by DNS name (`/dns`, `/dns4`,
/// `/dns6`, or `/dnsaddr`). The node cannot dial such an address, because the
/// DNS transport of libp2p is not compiled in.
pub fn refuse_dns(multiaddr: &Multiaddr) -> Result<(), String> {
    let names_dns_host = multiaddr.iter().any(|protocol| {
        matches!(
            protocol,
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
        )
    });
    if names_dns_host {
        return Err(format!(
            "multiaddress `{multiaddr}` names a host by DNS name, which is not supported, \
             because the DNS transport of libp2p is not compiled in; give an IP address instead"
        ));
    }

    Ok(())
}

/// The first IP address named by a multiaddress, if any.
pub fn ip_of(multiaddr: &Multiaddr) -> Option<IpAddr> {
    multiaddr.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// Whether the multiaddress routes through a relay (`/p2p-circuit`).
pub fn is_relayed(multiaddr: &Multiaddr) -> bool {
    multiaddr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
}

/// The socket address of a direct connection at the given multiaddress.
///
/// The multiaddress must start with an IP address followed by a TCP or a UDP
/// port, as in `/ip4/1.2.3.4/tcp/9902` or `/ip6/::1/udp/9901/quic-v1`. Any
/// components after the port, such as `/quic-v1` or `/p2p/<peer id>`, are
/// ignored. Relayed multiaddresses yield `None`, because the socket address
/// they contain is that of the relay.
pub fn direct_socket_addr(multiaddr: &Multiaddr) -> Option<SocketAddr> {
    if is_relayed(multiaddr) {
        return None;
    }

    let mut protocols = multiaddr.iter();
    let ip = match protocols.next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    let (Protocol::Tcp(port) | Protocol::Udp(port)) = protocols.next()? else {
        return None;
    };

    Some(SocketAddr::new(ip, port))
}

/// The socket address with its IP address in canonical form: an IPv4-mapped
/// IPv6 address, such as `[::ffff:1.2.3.4]:9898`, becomes the IPv4 address it
/// maps, `1.2.3.4:9898`. A listener on `::` reports IPv4 peers in the mapped
/// form, while other sockets report them in the IPv4 form.
pub fn canonical_socket_addr(socket_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(socket_addr.ip().to_canonical(), socket_addr.port())
}

/// The multiaddress of a TCP endpoint: `/ip4/<ip>/tcp/<port>`, or the IPv6
/// equivalent.
pub fn socketaddr_to_multiaddr(socket_addr: SocketAddr) -> Multiaddr {
    Multiaddr::from(socket_addr.ip()).with(Protocol::Tcp(socket_addr.port()))
}

/// The multiaddress of a QUIC endpoint: `/ip4/<ip>/udp/<port>/quic-v1`, or the
/// IPv6 equivalent.
pub fn socketaddr_to_quic_multiaddr(socket_addr: SocketAddr) -> Multiaddr {
    Multiaddr::from(socket_addr.ip())
        .with(Protocol::Udp(socket_addr.port()))
        .with(Protocol::QuicV1)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV4;
    use std::net::SocketAddrV6;

    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    use super::*;
    use crate::tests::shared::globalstate::get_dummy_socket_address;

    const PEER_ID: &str = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

    fn multiaddr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn ips_parse_as_themselves() {
        assert_eq!(
            Ok(IpAddr::V4(Ipv4Addr::new(139, 162, 193, 206))),
            parse_ip_or_multiaddr("139.162.193.206")
        );
        assert_eq!(
            Ok(IpAddr::V6(
                "2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9".parse().unwrap()
            )),
            parse_ip_or_multiaddr("2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9")
        );
    }

    #[test]
    fn multiaddrs_parse_as_the_ip_they_name() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        for s in [
            "/ip4/8.8.4.4",
            "/ip4/8.8.4.4/tcp/9898",
            "/ip4/8.8.4.4/udp/1337/quic-v1",
            &format!("/ip4/8.8.4.4/tcp/9902/p2p/{PEER_ID}"),
        ] {
            assert_eq!(Ok(ip), parse_ip_or_multiaddr(s), "{s}");
        }
    }

    #[test]
    fn multiaddrs_with_dns_names_are_refused() {
        for s in [
            "/dns/example.com/udp/9901/quic-v1",
            "/dns4/example.com/tcp/9902",
            "/dns6/example.com/tcp/9902",
            "/dnsaddr/example.com",
        ] {
            let error = refuse_dns(&multiaddr(s)).unwrap_err();
            assert!(error.contains("DNS"), "{error}");
            assert!(parse_ip_or_multiaddr(s).unwrap_err().contains("DNS"), "{s}");
        }

        for s in [
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            "/ip6/::1/tcp/9902",
            &format!("/p2p/{PEER_ID}"),
        ] {
            assert_eq!(Ok(()), refuse_dns(&multiaddr(s)), "{s}");
        }
    }

    #[test]
    fn multiaddrs_without_a_direct_ip_are_refused() {
        for s in [
            "/dns4/example.com/tcp/9898",
            &format!("/p2p/{PEER_ID}"),
            &format!("/ip4/8.8.4.4/tcp/9902/p2p/{PEER_ID}/p2p-circuit"),
            "not an address",
            "1.2.3.4:9898",
        ] {
            assert!(parse_ip_or_multiaddr(s).is_err(), "{s}");
        }
    }

    #[test]
    fn direct_socket_addr_accepts_tcp_and_udp() {
        let socket_addr = SocketAddr::from(([1, 2, 3, 4], 9902));
        assert_eq!(
            Some(socket_addr),
            direct_socket_addr(&multiaddr("/ip4/1.2.3.4/tcp/9902"))
        );
        assert_eq!(
            Some(SocketAddr::from(([1, 2, 3, 4], 9901))),
            direct_socket_addr(&multiaddr("/ip4/1.2.3.4/udp/9901/quic-v1"))
        );
        assert_eq!(
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 40123)),
            direct_socket_addr(&multiaddr(&format!("/ip6/::1/tcp/40123/p2p/{PEER_ID}")))
        );
    }

    #[test]
    fn direct_socket_addr_refuses_incomplete_and_relayed_addresses() {
        for s in [
            "/ip4/1.2.3.4",
            "/dns4/example.com/tcp/9902",
            "/tcp/9902",
            &format!("/p2p/{PEER_ID}"),
            &format!("/ip4/1.2.3.4/tcp/9902/p2p/{PEER_ID}/p2p-circuit"),
        ] {
            assert_eq!(None, direct_socket_addr(&multiaddr(s)), "{s}");
        }
    }

    #[test]
    fn canonical_socket_addr_unmaps_ipv4_addresses_only() {
        let ipv4 = SocketAddr::from(([198, 51, 100, 7], 9898));
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped()),
            9898,
        );
        assert_eq!(ipv4, canonical_socket_addr(mapped));
        assert_eq!(ipv4, canonical_socket_addr(ipv4));

        let ipv6 = SocketAddr::new(IpAddr::V6("2001:db8::7".parse().unwrap()), 9898);
        assert_eq!(ipv6, canonical_socket_addr(ipv6));
    }

    #[test]
    fn socketaddr_multiaddr_round_trip_unit() {
        let socket_address = get_dummy_socket_address(0);
        let multiaddr = socketaddr_to_multiaddr(socket_address);
        assert_eq!(Some(socket_address), direct_socket_addr(&multiaddr));

        let quic_multiaddr = socketaddr_to_quic_multiaddr(socket_address);
        assert_eq!(Some(socket_address), direct_socket_addr(&quic_multiaddr));
    }

    #[proptest]
    fn ipv4_multiaddr_round_trip_prop(ipv4: SocketAddrV4) {
        let socket_addr = SocketAddr::from(ipv4);
        for multiaddr in [
            socketaddr_to_multiaddr(socket_addr),
            socketaddr_to_quic_multiaddr(socket_addr),
        ] {
            prop_assert_eq!(Some(socket_addr), direct_socket_addr(&multiaddr));
        }
    }

    #[proptest]
    fn ipv6_multiaddr_round_trip_prop(ipv6: SocketAddrV6) {
        let socket_addr = SocketAddr::from(ipv6);
        for multiaddr in [
            socketaddr_to_multiaddr(socket_addr),
            socketaddr_to_quic_multiaddr(socket_addr),
        ] {
            // The scope ID and flow info are not part of a multiaddress.
            let round_trip = direct_socket_addr(&multiaddr).unwrap();
            prop_assert_eq!(socket_addr.ip(), round_trip.ip());
            prop_assert_eq!(socket_addr.port(), round_trip.port());
        }
    }
}
