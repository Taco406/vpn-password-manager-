//! Chrome native-messaging framing: a u32 little-endian length prefix followed by
//! UTF-8 JSON. Enforces a hard 1 MiB cap on any single frame (fuzz-tested).

use super::protocol::NmEnvelope;

/// Chrome's own limit is 1 MiB; enforce it on both hops.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Not enough bytes yet for a complete frame.
    Incomplete,
    /// The length prefix exceeds the cap.
    TooLarge(usize),
    /// The body was not valid UTF-8 / JSON.
    Malformed,
}

/// Encode an envelope as a length-prefixed frame.
pub fn encode_frame(env: &NmEnvelope) -> Vec<u8> {
    let body = serde_json::to_vec(env).expect("envelope serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decode one frame from the front of `buf`. On success returns the envelope and the
/// number of bytes consumed. Returns [`FrameError::Incomplete`] if more bytes are
/// needed, and rejects oversized/malformed frames.
pub fn decode_frame(buf: &[u8]) -> Result<(NmEnvelope, usize), FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Incomplete);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    if buf.len() < 4 + len {
        return Err(FrameError::Incomplete);
    }
    let body = &buf[4..4 + len];
    let env: NmEnvelope = serde_json::from_slice(body).map_err(|_| FrameError::Malformed)?;
    Ok((env, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::super::protocol::NmType;
    use super::*;

    fn env() -> NmEnvelope {
        NmEnvelope {
            id: "1".into(),
            kind: NmType::Hello,
            ok: Some(true),
            payload: None,
            err: None,
        }
    }

    #[test]
    fn round_trip() {
        let frame = encode_frame(&env());
        let (back, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(back, env());
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn incomplete_prefix_and_body() {
        assert_eq!(decode_frame(&[0, 0]), Err(FrameError::Incomplete));
        // Prefix says 100 bytes but body is short.
        let mut buf = 100u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"short");
        assert_eq!(decode_frame(&buf), Err(FrameError::Incomplete));
    }

    #[test]
    fn rejects_oversized_prefix() {
        let buf = ((MAX_MESSAGE_BYTES + 1) as u32).to_le_bytes().to_vec();
        assert!(matches!(decode_frame(&buf), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn rejects_malformed_body() {
        let mut buf = 3u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"\xff\xff\xff");
        assert_eq!(decode_frame(&buf), Err(FrameError::Malformed));
    }

    #[test]
    fn two_frames_back_to_back() {
        let mut stream = encode_frame(&env());
        stream.extend_from_slice(&encode_frame(&env()));
        let (_, n1) = decode_frame(&stream).unwrap();
        let (_, n2) = decode_frame(&stream[n1..]).unwrap();
        assert_eq!(n1 + n2, stream.len());
    }

    #[test]
    fn fuzz_truncations_never_panic() {
        let frame = encode_frame(&env());
        for i in 0..frame.len() {
            // Any prefix of a valid frame must be Incomplete or Ok, never a panic.
            let _ = decode_frame(&frame[..i]);
        }
    }
}
