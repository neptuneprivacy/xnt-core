//! The XNT handshake on libp2p connections.
//!
//! The handshake is one frame in each direction, in the format of the legacy
//! TCP stack: a big-endian `u32` length followed by a bincode-encoded
//! [`PeerMessage::Handshake`]. The side that opens the substream sends
//! [`MAGIC_STRING_REQUEST`]; the side that accepts it answers with
//! [`MAGIC_STRING_RESPONSE`].
//!
//! Frames are read with `read_exact`, so that no byte beyond the handshake is
//! consumed. The stream is afterwards handed to the peer loop through
//! [`bridge_libp2p_stream`](super::bridge::bridge_libp2p_stream), and any
//! message the peer sent right after its handshake is still there.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use bincode::Options;
use const_format::concatcp;
use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use libp2p::core::upgrade::InboundUpgrade;
use libp2p::core::upgrade::OutboundUpgrade;
use libp2p::core::upgrade::UpgradeInfo;
use libp2p::Stream;
use libp2p::StreamProtocol;

use crate::application::config::network::Network;
use crate::application::loops::connect_to_peers::system_time_diff_seconds;
use crate::application::loops::connect_to_peers::version_follows_rule_set;
use crate::application::loops::connect_to_peers::versions_are_compatible;
use crate::application::loops::connect_to_peers::MAX_PEER_FRAME_LENGTH_IN_BYTES;
use crate::application::loops::connect_to_peers::PEER_TIME_DIFFERENCE_THRESHOLD_IN_SECONDS;
use crate::application::network::stack::XNT_PROTOCOL_STR;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::protocol::peer::handshake_data::VersionString;
use crate::protocol::peer::PeerMessage;
use crate::protocol::peer::PeerMessageKind;
use crate::MAGIC_STRING_REQUEST;
use crate::MAGIC_STRING_RESPONSE;

/// The protocol ID of the handshake substream.
pub(crate) const HANDSHAKE_PROTOCOL_STR: &str = concatcp!(XNT_PROTOCOL_STR, "handshake/1.0.0");

/// Size of the length prefix of a frame.
const LENGTH_FIELD_LEN: usize = 4;

/// The protocol negotiation and handshake logic for a stream.
///
/// The [`HandshakeUpgrade`] is a blueprint for libp2p to "upgrade" a raw socket
/// into a verified connection. It carries the `local_handshake` so it can be
/// transmitted to the remote peer during the negotiation phase.
pub(crate) struct HandshakeUpgrade {
    pub(crate) local_handshake: HandshakeData,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandshakeError {
    #[error("IO Error({0})")]
    IO(#[from] std::io::Error),

    #[error("ValidationError({0})")]
    Validation(#[from] HandshakeValidationError),
}

/// Why a remote handshake was refused, judging from the two handshakes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HandshakeValidationError {
    #[error("remote sent the wrong magic value")]
    WrongMagic,

    #[error("connect to self")]
    SelfConnect,

    #[error("local network ({local}) =/= remote network ({remote})")]
    NetworkMismatch { local: Network, remote: Network },

    #[error("local version ({local}) is incompatible with remote version ({remote})")]
    IncompatibleVersion {
        local: VersionString,
        remote: VersionString,
    },

    #[error("remote version ({remote}) does not follow the consensus rule set {rule_set}")]
    RuleSetNotFollowed {
        remote: VersionString,
        rule_set: ConsensusRuleSet,
    },

    #[error("clock difference between local and remote too large")]
    ExcessiveClockDifference {
        local: SystemTime,
        remote: SystemTime,
    },
}

impl HandshakeUpgrade {
    /// Determine whether the remote handshake is acceptable, up to everything
    /// that can be checked without access to the node's state.
    ///
    /// Applies the rules of the legacy TCP stack: same network, a different
    /// instance, compatible versions, a version that follows the consensus rule
    /// set of the local tip, and clocks that agree. Bans, peer standing, the
    /// number of peers, and duplicate connections are for the caller to check.
    pub(crate) fn validate(
        local: &HandshakeData,
        remote: &HandshakeData,
    ) -> Result<(), HandshakeValidationError> {
        if local.instance_id == remote.instance_id {
            return Err(HandshakeValidationError::SelfConnect);
        }

        if local.network != remote.network {
            return Err(HandshakeValidationError::NetworkMismatch {
                local: local.network,
                remote: remote.network,
            });
        }

        if !versions_are_compatible(&local.version, &remote.version) {
            return Err(HandshakeValidationError::IncompatibleVersion {
                local: local.version,
                remote: remote.version,
            });
        }

        let rule_set = ConsensusRuleSet::infer_from(local.network, local.tip_header.height);
        if !version_follows_rule_set(&remote.version, rule_set) {
            return Err(HandshakeValidationError::RuleSetNotFollowed {
                remote: remote.version,
                rule_set,
            });
        }

        let now = SystemTime::now();
        if system_time_diff_seconds(remote.timestamp, now)
            > PEER_TIME_DIFFERENCE_THRESHOLD_IN_SECONDS
        {
            return Err(HandshakeValidationError::ExcessiveClockDifference {
                local: now,
                remote: remote.timestamp,
            });
        }

        Ok(())
    }

    /// Run the handshake as the side that accepted the substream: read the
    /// opener's handshake, check it, and answer with our own.
    ///
    /// Our handshake is only sent to a peer that passes the checks.
    pub(super) async fn accept<C>(self, mut socket: C) -> Result<(HandshakeData, C), HandshakeError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let remote_handshake = Self::decode_handshake(&mut socket, MAGIC_STRING_REQUEST).await?;
        Self::check(&self.local_handshake, &remote_handshake)?;
        Self::encode_handshake(&mut socket, MAGIC_STRING_RESPONSE, self.local_handshake).await?;

        Ok((remote_handshake, socket))
    }

    /// Run the handshake as the side that opened the substream: send our
    /// handshake, then read and check the answer.
    pub(super) async fn open<C>(self, mut socket: C) -> Result<(HandshakeData, C), HandshakeError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        Self::encode_handshake(&mut socket, MAGIC_STRING_REQUEST, self.local_handshake).await?;
        let remote_handshake = Self::decode_handshake(&mut socket, MAGIC_STRING_RESPONSE).await?;
        Self::check(&self.local_handshake, &remote_handshake)?;

        Ok((remote_handshake, socket))
    }

    fn check(local: &HandshakeData, remote: &HandshakeData) -> Result<(), HandshakeError> {
        Self::validate(local, remote).map_err(|e| {
            tracing::warn!("Handshake failed: {e}.");
            HandshakeError::Validation(e)
        })
    }

    /// The bincode options of peer messages, as used by the legacy TCP stack.
    fn bincode_options() -> impl Options {
        bincode::DefaultOptions::new().with_limit(MAX_PEER_FRAME_LENGTH_IN_BYTES as u64)
    }

    /// The most bytes a handshake frame may have.
    fn max_frame_length() -> usize {
        PeerMessageKind::Handshake
            .max_frame_length()
            .unwrap_or(MAX_PEER_FRAME_LENGTH_IN_BYTES)
    }

    /// Write one handshake frame. The timestamp is set to the current time.
    async fn encode_handshake<S>(
        socket: &mut S,
        magic_value: &[u8; 15],
        mut handshake: HandshakeData,
    ) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        handshake.timestamp = SystemTime::now();
        let message = PeerMessage::Handshake {
            magic_value: *magic_value,
            data: Box::new(handshake),
        };
        let payload = Self::bincode_options()
            .serialize(&message)
            .map_err(invalid_data)?;
        let length = u32::try_from(payload.len()).map_err(invalid_data)?;

        let mut frame = Vec::with_capacity(LENGTH_FIELD_LEN + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        socket.write_all(&frame).await?;
        socket.flush().await?;

        Ok(())
    }

    /// Read exactly one handshake frame and check its magic value.
    ///
    /// The announced length is checked against the limit for handshake
    /// messages before any of the payload is read.
    async fn decode_handshake<S>(
        socket: &mut S,
        expected_magic_value: &[u8; 15],
    ) -> Result<HandshakeData, HandshakeError>
    where
        S: AsyncRead + Unpin,
    {
        let mut length_field = [0u8; LENGTH_FIELD_LEN];
        socket.read_exact(&mut length_field).await?;
        let length = usize::try_from(u32::from_be_bytes(length_field)).map_err(invalid_data)?;
        let limit = Self::max_frame_length();
        if length > limit {
            return Err(invalid_data(format!(
                "handshake frame of {length} bytes exceeds the limit of {limit} bytes"
            ))
            .into());
        }

        let mut payload = vec![0u8; length];
        socket.read_exact(&mut payload).await?;
        let message: PeerMessage = Self::bincode_options()
            .deserialize(&payload)
            .map_err(invalid_data)?;

        let PeerMessage::Handshake { magic_value, data } = message else {
            return Err(invalid_data("expected a handshake message").into());
        };
        if magic_value != *expected_magic_value {
            tracing::warn!(
                "Handshake failed: {}.",
                HandshakeValidationError::WrongMagic
            );
            return Err(HandshakeValidationError::WrongMagic.into());
        }

        Ok(*data)
    }
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

impl UpgradeInfo for HandshakeUpgrade {
    type Info = StreamProtocol;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(StreamProtocol::new(HANDSHAKE_PROTOCOL_STR))
    }
}

impl<C> InboundUpgrade<C> for HandshakeUpgrade
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (HandshakeData, C);
    type Error = HandshakeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    /// Execute the handshake logic for an incoming substream.
    fn upgrade_inbound(self, socket: C, _info: Self::Info) -> Self::Future {
        Box::pin(self.accept(socket))
    }
}

impl<C> OutboundUpgrade<C> for HandshakeUpgrade
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (HandshakeData, C);
    type Error = HandshakeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    /// Execute the handshake logic for an outgoing substream.
    fn upgrade_outbound(self, socket: C, _info: Self::Info) -> Self::Future {
        Box::pin(self.open(socket))
    }
}

/// The outcome of a completed protocol handshake.
///
/// This enum encapsulates the successful handshake-exchange with a remote peer.
/// It acts as the final hand-off mechanism between the low-level
/// [`HandshakeUpgrade`] and the higher-level
/// [`StreamGateway`](super::gateway::StreamGateway).
#[derive(Debug)]
pub(crate) enum HandshakeResult {
    /// The handshake was successful.
    ///
    /// This variant carries both the peer's handshake and the communication
    /// channel itself, ensuring they are never separated.
    Success {
        remote_handshake: Box<HandshakeData>,
        stream: Stream,
        /// Whether the remote opened the connection.
        inbound: bool,
    },

    /// The handshake failed, or did not complete in time.
    Failed,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::time::Duration;

    use futures::io::Cursor;
    use proptest::collection::vec;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;
    use crate::protocol::consensus::block::block_header::BlockHeader;
    use crate::protocol::peer::handshake_data::ExtraDataString;
    use crate::tests::shared::globalstate::get_dummy_handshake_data_for_genesis;

    /// Handshakes with arbitrary fields, on any network.
    pub(crate) fn arb_handshake_data() -> BoxedStrategy<HandshakeData> {
        (
            arb::<BlockHeader>(),
            proptest::option::of(0u16..=u16::MAX),
            proptest::sample::select(vec![
                Network::Main,
                Network::TestnetMock,
                Network::RegTest,
                Network::Testnet(0),
                Network::Testnet(7),
            ]),
            arb::<u128>(),
            (0u8..5, 0u8..50, 0u8..200),
            arb::<bool>(),
            arb::<bool>(),
            0u64..4_000_000_000,
            "[ -~]{0,255}",
        )
            .prop_map(
                |(
                    tip_header,
                    listen_port,
                    network,
                    instance_id,
                    (major, minor, patch),
                    is_archival_node,
                    is_bootstrapper_node,
                    timestamp_secs,
                    extra_data,
                )| HandshakeData {
                    tip_header,
                    listen_port,
                    network,
                    instance_id,
                    version: VersionString::try_from_str(format!("{major}.{minor}.{patch}"))
                        .unwrap(),
                    is_archival_node,
                    is_bootstrapper_node,
                    timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp_secs),
                    extra_data: ExtraDataString::try_from_str(&extra_data).unwrap(),
                },
            )
            .boxed()
    }

    fn handshake_with_version(network: Network, version: &str) -> HandshakeData {
        let mut handshake = get_dummy_handshake_data_for_genesis(network);
        handshake.version = VersionString::try_from_str(version).unwrap();
        handshake
    }

    async fn encode_to_vec(magic_value: &[u8; 15], handshake: HandshakeData) -> Vec<u8> {
        let mut buffer = Vec::new();
        HandshakeUpgrade::encode_handshake(&mut Cursor::new(&mut buffer), magic_value, handshake)
            .await
            .unwrap();
        buffer
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_encoding_roundtrip(
        #[strategy(arb_handshake_data())] handshake: HandshakeData,
    ) {
        let buffer = encode_to_vec(MAGIC_STRING_REQUEST, handshake).await;
        let decoded =
            HandshakeUpgrade::decode_handshake(&mut Cursor::new(buffer), MAGIC_STRING_REQUEST)
                .await
                .unwrap();

        // Encoding refreshes the timestamp; everything else is unchanged.
        prop_assert_eq!(
            HandshakeData {
                timestamp: decoded.timestamp,
                ..handshake
            },
            decoded
        );
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_frame_is_a_legacy_handshake_frame(
        #[strategy(arb_handshake_data())] handshake: HandshakeData,
    ) {
        let buffer = encode_to_vec(MAGIC_STRING_RESPONSE, handshake).await;

        let (length_field, payload) = buffer.split_at(LENGTH_FIELD_LEN);
        let length = u32::from_be_bytes(length_field.try_into().unwrap());
        prop_assert_eq!(payload.len(), usize::try_from(length).unwrap());
        prop_assert!(payload.len() <= HandshakeUpgrade::max_frame_length());

        let message: PeerMessage = bincode::DefaultOptions::new().deserialize(payload).unwrap();
        let PeerMessage::Handshake { magic_value, data } = message else {
            panic!("expected a handshake message");
        };
        prop_assert_eq!(*MAGIC_STRING_RESPONSE, magic_value);
        prop_assert_eq!(handshake.instance_id, data.instance_id);
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_decoding_of_arbitrary_bytes_returns(
        #[strategy(vec(arb::<u8>(), 0..4096))] buffer: Vec<u8>,
    ) {
        let mut read_cursor = Cursor::new(buffer);
        let _ = HandshakeUpgrade::decode_handshake(&mut read_cursor, MAGIC_STRING_REQUEST).await;
    }

    #[tokio::test]
    async fn wrong_magic_value_is_refused() {
        let handshake = get_dummy_handshake_data_for_genesis(Network::Main);
        for (sent, expected) in [
            (MAGIC_STRING_RESPONSE, MAGIC_STRING_REQUEST),
            (MAGIC_STRING_REQUEST, MAGIC_STRING_RESPONSE),
            (b"7B8AB7FC438F411", MAGIC_STRING_REQUEST),
            (b"Hello Neptune!\n", MAGIC_STRING_RESPONSE),
        ] {
            let buffer = encode_to_vec(sent, handshake).await;
            let result =
                HandshakeUpgrade::decode_handshake(&mut Cursor::new(buffer), expected).await;
            assert!(
                matches!(
                    result,
                    Err(HandshakeError::Validation(
                        HandshakeValidationError::WrongMagic
                    ))
                ),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn handshake_frame_above_the_handshake_limit_is_refused_before_reading_it() {
        let limit = HandshakeUpgrade::max_frame_length();
        assert_eq!(64 * 1024, limit);

        // Only the length prefix is sent: the frame must be refused without
        // waiting for the payload.
        let length = u32::try_from(limit + 1).unwrap();
        let mut socket = Cursor::new(length.to_be_bytes().to_vec());
        let result = HandshakeUpgrade::decode_handshake(&mut socket, MAGIC_STRING_REQUEST).await;
        let Err(HandshakeError::IO(error)) = result else {
            panic!("expected an I/O error, got {result:?}");
        };
        assert_eq!(std::io::ErrorKind::InvalidData, error.kind());
        assert_eq!(u64::try_from(LENGTH_FIELD_LEN).unwrap(), socket.position());
    }

    #[tokio::test]
    async fn frame_of_another_kind_is_refused() {
        let payload = bincode::DefaultOptions::new()
            .serialize(&PeerMessage::Bye)
            .unwrap();
        let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        frame.extend(payload);
        let result =
            HandshakeUpgrade::decode_handshake(&mut Cursor::new(frame), MAGIC_STRING_REQUEST).await;
        assert!(matches!(result, Err(HandshakeError::IO(_))), "{result:?}");
    }

    #[test]
    fn matching_handshakes_are_accepted() {
        for network in [Network::Main, Network::RegTest, Network::Testnet(0)] {
            let local = handshake_with_version(network, "0.4.0");
            let remote = handshake_with_version(network, "0.3.0");
            assert_eq!(Ok(()), HandshakeUpgrade::validate(&local, &remote));
        }
    }

    #[test]
    fn handshake_with_own_instance_id_is_refused() {
        let local = get_dummy_handshake_data_for_genesis(Network::Main);
        assert_eq!(
            Err(HandshakeValidationError::SelfConnect),
            HandshakeUpgrade::validate(&local, &local)
        );
    }

    #[test]
    fn handshake_from_another_network_is_refused() {
        let local = get_dummy_handshake_data_for_genesis(Network::Main);
        for network in [Network::TestnetMock, Network::RegTest, Network::Testnet(0)] {
            let remote = get_dummy_handshake_data_for_genesis(network);
            assert_eq!(
                Err(HandshakeValidationError::NetworkMismatch {
                    local: Network::Main,
                    remote: network,
                }),
                HandshakeUpgrade::validate(&local, &remote)
            );
        }
    }

    #[test]
    fn handshake_with_incompatible_version_is_refused() {
        let local = handshake_with_version(Network::Main, "0.4.0");
        for version in ["0.0.5", "not-a-version"] {
            let remote = handshake_with_version(Network::Main, version);
            assert!(
                matches!(
                    HandshakeUpgrade::validate(&local, &remote),
                    Err(HandshakeValidationError::IncompatibleVersion { .. })
                ),
                "{version}"
            );
        }
    }

    #[test]
    fn handshake_with_version_before_the_rule_set_of_the_tip_is_refused() {
        // Every block of these networks follows `LeviathanSettlement`.
        let local = handshake_with_version(Network::RegTest, "0.4.0");
        let remote = handshake_with_version(Network::RegTest, "0.2.9");
        assert_eq!(
            Err(HandshakeValidationError::RuleSetNotFollowed {
                remote: remote.version,
                rule_set: ConsensusRuleSet::LeviathanSettlement,
            }),
            HandshakeUpgrade::validate(&local, &remote)
        );
    }

    #[test]
    fn handshake_from_a_clock_too_far_off_is_refused() {
        let local = get_dummy_handshake_data_for_genesis(Network::Main);
        for offset in [Duration::from_secs(120), Duration::from_secs(3600)] {
            for timestamp in [SystemTime::now() + offset, SystemTime::now() - offset] {
                let mut remote = get_dummy_handshake_data_for_genesis(Network::Main);
                remote.timestamp = timestamp;
                assert!(matches!(
                    HandshakeUpgrade::validate(&local, &remote),
                    Err(HandshakeValidationError::ExcessiveClockDifference { .. })
                ));
            }
        }
    }

    #[tokio::test]
    async fn opener_and_acceptor_complete_the_handshake() {
        let network = Network::Main;
        let opener = get_dummy_handshake_data_for_genesis(network);
        let acceptor = get_dummy_handshake_data_for_genesis(network);
        let (opener_socket, acceptor_socket) = tokio::io::duplex(1 << 16);

        let (opened, accepted) = tokio::join!(
            HandshakeUpgrade {
                local_handshake: opener
            }
            .open(opener_socket.compat()),
            HandshakeUpgrade {
                local_handshake: acceptor
            }
            .accept(acceptor_socket.compat()),
        );

        let (opener_saw, _) = opened.unwrap();
        let (acceptor_saw, _) = accepted.unwrap();
        assert_eq!(acceptor.instance_id, opener_saw.instance_id);
        assert_eq!(opener.instance_id, acceptor_saw.instance_id);
    }

    #[tokio::test]
    async fn acceptor_refuses_a_peer_from_another_network_without_answering() {
        let opener = get_dummy_handshake_data_for_genesis(Network::Testnet(0));
        let acceptor = get_dummy_handshake_data_for_genesis(Network::Main);
        let (opener_socket, acceptor_socket) = tokio::io::duplex(1 << 16);

        let (opened, accepted) = tokio::join!(
            HandshakeUpgrade {
                local_handshake: opener
            }
            .open(opener_socket.compat()),
            HandshakeUpgrade {
                local_handshake: acceptor
            }
            .accept(acceptor_socket.compat()),
        );

        assert!(matches!(
            accepted,
            Err(HandshakeError::Validation(
                HandshakeValidationError::NetworkMismatch { .. }
            ))
        ));
        assert!(matches!(opened, Err(HandshakeError::IO(_))));
    }

    #[test]
    fn handshake_protocol_is_specific_to_xnt() {
        assert_eq!("/xnt/handshake/1.0.0", HANDSHAKE_PROTOCOL_STR);
        let protocol = HandshakeUpgrade {
            local_handshake: get_dummy_handshake_data_for_genesis(Network::Main),
        }
        .protocol_info()
        .next()
        .unwrap();
        assert_eq!(HANDSHAKE_PROTOCOL_STR, protocol.as_ref());
    }
}
