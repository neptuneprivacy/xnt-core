//! Length-delimited framing of peer messages with a size limit per kind of
//! message.
//!
//! A frame is a big-endian `u32` length followed by that many bytes of one
//! bincode-encoded [`PeerMessage`](crate::protocol::peer::PeerMessage). The
//! codec reads the kind of message from the first bytes of the payload and
//! refuses the frame as soon as its announced length exceeds what a message of
//! that kind can legitimately need, long before the whole frame has been
//! received and buffered. Until the handshake has completed, every frame is
//! held to the limit of a handshake message.

use std::io;

use bincode::Options;
use bytes::Bytes;
use bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;

use crate::application::loops::connect_to_peers::MAX_PEER_FRAME_LENGTH_IN_BYTES;
use crate::protocol::peer::PeerMessageKind;

/// Size of the length prefix of a frame, as [`LengthDelimitedCodec`] writes
/// it by default.
const LENGTH_FIELD_LEN: usize = 4;

/// Payload bytes that suffice to read the kind of message. A bincode variant
/// index takes at most five bytes.
const KIND_PEEK_LEN: usize = 5;

/// The most bytes a frame of a kind unknown to this version may have. Such a
/// frame is passed on, so that messages added by later versions do not end the
/// connection, but only if it is small.
const UNKNOWN_KIND_FRAME_LIMIT: usize = 64 * 1024;

/// A frame announced more bytes than a message of its kind may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{kind} message of {frame_len} bytes exceeds the limit of {limit} bytes")]
pub(crate) struct OversizedFrame {
    pub(crate) kind: PeerMessageKind,
    pub(crate) frame_len: usize,
    pub(crate) limit: usize,
}

#[derive(Debug)]
pub(crate) struct PeerFrameCodec {
    inner: LengthDelimitedCodec,

    /// Whether the handshake with the peer has completed. Before, every frame
    /// is held to the limit of a handshake message.
    handshake_completed: bool,

    /// Whether the frame being received has passed the check against the
    /// limit for its kind.
    checked: bool,
}

impl Default for PeerFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerFrameCodec {
    pub(crate) fn new() -> Self {
        let mut inner = LengthDelimitedCodec::new();
        inner.set_max_frame_length(MAX_PEER_FRAME_LENGTH_IN_BYTES);
        Self {
            inner,
            handshake_completed: false,
            checked: false,
        }
    }

    /// Lift the limit of a handshake message from the frames that follow.
    pub(crate) fn complete_handshake(&mut self) {
        self.handshake_completed = true;
    }

    /// The most bytes a frame carrying a message of the given kind may have.
    fn frame_limit(&self, kind: PeerMessageKind) -> usize {
        let kind = if self.handshake_completed {
            kind
        } else {
            PeerMessageKind::Handshake
        };
        kind.max_frame_length()
            .map_or(MAX_PEER_FRAME_LENGTH_IN_BYTES, |limit| {
                limit.min(MAX_PEER_FRAME_LENGTH_IN_BYTES)
            })
    }

    /// Check the frame whose length prefix and first payload bytes are in
    /// `src`. Returns `Ok(false)` if more bytes are needed to decide.
    fn check(&self, src: &[u8]) -> io::Result<bool> {
        let Some(length_field) = src.get(..LENGTH_FIELD_LEN) else {
            return Ok(false);
        };
        let frame_len = u32::from_be_bytes(length_field.try_into().unwrap()) as usize;
        let payload = &src[LENGTH_FIELD_LEN..];
        let peek_len = frame_len.min(KIND_PEEK_LEN);
        let available = &payload[..payload.len().min(peek_len)];

        // Only the tag is read; the payload continues after it. Only wait for
        // more bytes while they could still complete the tag.
        let tag = match bincode::DefaultOptions::new().deserialize_from::<_, u32>(available) {
            Ok(tag) => tag,
            Err(_) if available.len() < peek_len => return Ok(false),
            Err(_) => return Err(invalid_data("frame does not start with a kind of message")),
        };

        let Some(kind) = PeerMessageKind::from_bincode_tag(tag) else {
            let limit = UNKNOWN_KIND_FRAME_LIMIT.min(self.frame_limit(PeerMessageKind::Handshake));
            if frame_len > limit {
                return Err(invalid_data(format!(
                    "message of unknown kind {tag} of {frame_len} bytes exceeds the limit of \
                     {limit} bytes"
                )));
            }
            return Ok(true);
        };

        let limit = self.frame_limit(kind);
        if frame_len > limit {
            return Err(invalid_data(OversizedFrame {
                kind,
                frame_len,
                limit,
            }));
        }

        Ok(true)
    }
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl Decoder for PeerFrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if !self.checked {
            if !self.check(src)? {
                return Ok(None);
            }
            self.checked = true;
        }

        let frame = self.inner.decode(src)?;
        if frame.is_some() {
            self.checked = false;
        }

        Ok(frame)
    }
}

impl Encoder<Bytes> for PeerFrameCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        self.inner.encode(item, dst)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use super::*;
    use crate::protocol::peer::PeerMessage;

    fn frame(payload: Vec<u8>) -> BytesMut {
        let mut dst = BytesMut::new();
        PeerFrameCodec::new()
            .encode(Bytes::from(payload), &mut dst)
            .unwrap();
        dst
    }

    #[test]
    fn frames_are_decoded_as_their_bytes_arrive() {
        let options = bincode::DefaultOptions::new();
        let messages = [PeerMessage::PeerListRequest, PeerMessage::Bye];
        let mut wire = BytesMut::new();
        for message in &messages {
            wire.extend_from_slice(&frame(options.serialize(message).unwrap()));
        }

        let mut codec = PeerFrameCodec::new();
        let mut src = BytesMut::new();
        let mut decoded = vec![];
        for byte in wire {
            src.put_u8(byte);
            while let Some(payload) = codec.decode(&mut src).unwrap() {
                decoded.push(options.deserialize::<PeerMessage>(&payload).unwrap());
            }
        }

        assert_eq!(messages.to_vec(), decoded);
    }

    #[test]
    fn block_sized_frames_pass_once_the_handshake_has_completed() {
        let options = bincode::DefaultOptions::new();
        let mut payload = options.serialize(&(PeerMessageKind::Block as u32)).unwrap();
        payload.resize(1024 * 1024, 0);
        let mut src = frame(payload.clone());

        let mut codec = PeerFrameCodec::new();
        codec.complete_handshake();

        assert_eq!(
            Some(BytesMut::from(&payload[..])),
            codec.decode(&mut src).unwrap()
        );
    }
}
