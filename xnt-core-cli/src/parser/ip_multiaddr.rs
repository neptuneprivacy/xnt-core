use std::net::IpAddr;
use std::net::SocketAddr;

use multiaddr::Multiaddr;
use neptune_privacy::application::config::parser::multiaddr::ip_of;
use neptune_privacy::application::config::parser::multiaddr::is_relayed;
use neptune_privacy::application::config::parser::multiaddr::refuse_dns;
use neptune_privacy::application::config::parser::multiaddr::socketaddr_to_multiaddr;

/// Parse an IP address, a socket address, or a multiaddress that names an IP
/// address, such as `1.2.3.4`, `1.2.3.4:9898`, or
/// `/ip4/1.2.3.4/udp/9901/quic-v1`, into a multiaddress.
///
/// Relayed multiaddresses name the relay rather than the peer, so they are
/// refused, as are multiaddresses without an IP address, and those that name a
/// host by DNS name.
pub(crate) fn parse_ip_multiaddr(s: &str) -> Result<Multiaddr, String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Multiaddr::from(ip));
    }

    if let Ok(socket_addr) = s.parse::<SocketAddr>() {
        return Ok(socketaddr_to_multiaddr(socket_addr));
    }

    let multiaddr = s.parse::<Multiaddr>().map_err(|e| {
        format!("`{s}` is neither an IP address, a socket address, nor a multiaddress: {e}")
    })?;
    refuse_dns(&multiaddr)?;
    if is_relayed(&multiaddr) {
        return Err(format!(
            "multiaddress `{s}` names a relay rather than the peer"
        ));
    }
    if ip_of(&multiaddr).is_none() {
        return Err(format!("multiaddress `{s}` does not name an IP address"));
    }

    Ok(multiaddr)
}

/// Parse a multiaddress to dial, such as `/ip4/1.2.3.4/udp/9901/quic-v1`.
///
/// Multiaddresses that name a host by DNS name are refused, because the node
/// cannot resolve them.
pub(crate) fn parse_dial_multiaddr(s: &str) -> Result<Multiaddr, String> {
    let multiaddr = s
        .parse::<Multiaddr>()
        .map_err(|e| format!("`{s}` is not a multiaddress: {e}"))?;
    refuse_dns(&multiaddr)?;

    Ok(multiaddr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_addresses_become_multiaddresses() {
        assert_eq!(
            "/ip4/1.2.3.4",
            parse_ip_multiaddr("1.2.3.4").unwrap().to_string()
        );
        assert_eq!("/ip6/::1", parse_ip_multiaddr("::1").unwrap().to_string());
    }

    #[test]
    fn socket_addresses_become_tcp_multiaddresses() {
        assert_eq!(
            "/ip4/1.2.3.4/tcp/9898",
            parse_ip_multiaddr("1.2.3.4:9898").unwrap().to_string()
        );
        assert_eq!(
            "/ip6/::1/tcp/9898",
            parse_ip_multiaddr("[::1]:9898").unwrap().to_string()
        );
    }

    #[test]
    fn multiaddresses_naming_an_ip_address_are_kept() {
        for multiaddr in [
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            "/ip4/1.2.3.4/tcp/9902",
            "/ip6/::1/udp/9901/quic-v1",
        ] {
            assert_eq!(
                multiaddr,
                parse_ip_multiaddr(multiaddr).unwrap().to_string()
            );
        }
    }

    #[test]
    fn relayed_multiaddresses_are_refused() {
        let relayed = "/ip4/1.2.3.4/udp/9901/quic-v1/p2p-circuit";
        assert!(parse_ip_multiaddr(relayed).is_err());
    }

    #[test]
    fn multiaddresses_without_ip_address_are_refused() {
        assert!(parse_ip_multiaddr("/dns4/example.com/tcp/9902").is_err());
    }

    #[test]
    fn multiaddresses_with_dns_names_are_refused_with_a_clear_error() {
        for dns_multiaddr in [
            "/dns4/example.com/tcp/9902",
            "/dns/example.com/udp/9901/quic-v1",
        ] {
            assert!(parse_ip_multiaddr(dns_multiaddr)
                .unwrap_err()
                .contains("DNS"));
            assert!(parse_dial_multiaddr(dns_multiaddr)
                .unwrap_err()
                .contains("DNS"));
        }
    }

    #[test]
    fn dial_multiaddresses_are_kept() {
        for multiaddr in [
            "/ip4/1.2.3.4/udp/9901/quic-v1",
            "/ip4/1.2.3.4/tcp/9902",
            "/ip4/1.2.3.4/udp/9901/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA",
        ] {
            assert_eq!(
                multiaddr,
                parse_dial_multiaddr(multiaddr).unwrap().to_string()
            );
        }
    }

    #[test]
    fn malformed_addresses_are_refused() {
        for malformed in ["", "1.2.3", "1.2.3.4:", "ip4/1.2.3.4", "/ip4/1.2.3.4/udp"] {
            assert!(parse_ip_multiaddr(malformed).is_err(), "{malformed}");
        }
    }
}
