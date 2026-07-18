//! sentinel-nm-host — the Chrome native-messaging host.
//!
//! Chrome speaks to this process over stdio using u32-LE-length-prefixed JSON frames.
//! The host relays requests to the running desktop app over a local IPC socket and
//! returns its replies. When the desktop is not reachable (or locked), the host
//! answers vault requests with a `LOCKED` error carrying no credential data — the
//! extension must never receive secrets from a locked or absent desktop.

use sentinel_core::nm::{decode_frame, encode_frame, FrameError, NmEnvelope, NmType};
use std::io::{self, Read, Write};

fn main() {
    if let Err(e) = run(&mut io::stdin().lock(), &mut io::stdout().lock()) {
        eprintln!("sentinel-nm-host: {e}");
        std::process::exit(1);
    }
}

fn run<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Try to decode as many complete frames as we have buffered.
        loop {
            match decode_frame(&buf) {
                Ok((env, consumed)) => {
                    let reply = handle(&env);
                    output.write_all(&encode_frame(&reply))?;
                    output.flush()?;
                    buf.drain(..consumed);
                }
                Err(FrameError::Incomplete) => break,
                Err(FrameError::TooLarge(n)) => {
                    eprintln!("frame too large: {n} bytes");
                    return Ok(());
                }
                Err(FrameError::Malformed) => {
                    eprintln!("malformed frame; closing");
                    return Ok(());
                }
            }
        }
        let n = input.read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // EOF: Chrome closed the port.
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Route a request. Without a connected desktop, `hello` is answered locally and every
/// vault request returns `LOCKED` (no data).
fn handle(env: &NmEnvelope) -> NmEnvelope {
    match env.kind {
        NmType::Hello => NmEnvelope {
            id: env.id.clone(),
            kind: NmType::Hello,
            ok: Some(true),
            payload: Some(serde_json::json!({
                "caps": ["vault.search", "vault.fields.get", "vault.totp.get"],
                "appVersion": env!("CARGO_PKG_VERSION"),
                "locked": true,
            })),
            err: None,
        },
        // All credential-bearing requests are refused when the desktop is not
        // connected/unlocked. The real host forwards these over the IPC socket.
        _ => NmEnvelope::locked(&env.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::nm::NmErrorCode;

    fn frame(kind: NmType) -> Vec<u8> {
        encode_frame(&NmEnvelope {
            id: "1".into(),
            kind,
            ok: None,
            payload: None,
            err: None,
        })
    }

    #[test]
    fn hello_is_answered_locally() {
        let input = frame(NmType::Hello);
        let mut out = Vec::new();
        run(&mut input.as_slice(), &mut out).unwrap();
        let (reply, _) = decode_frame(&out).unwrap();
        assert_eq!(reply.ok, Some(true));
        assert!(reply.payload.unwrap()["locked"].as_bool().unwrap());
    }

    #[test]
    fn vault_requests_are_locked_without_desktop() {
        let input = frame(NmType::VaultFieldsGet);
        let mut out = Vec::new();
        run(&mut input.as_slice(), &mut out).unwrap();
        let (reply, _) = decode_frame(&out).unwrap();
        assert_eq!(reply.err.unwrap().code, NmErrorCode::Locked);
        assert!(reply.payload.is_none(), "no credential data while locked");
    }

    #[test]
    fn processes_multiple_frames() {
        let mut input = frame(NmType::Hello);
        input.extend_from_slice(&frame(NmType::VaultSearch));
        let mut out = Vec::new();
        run(&mut input.as_slice(), &mut out).unwrap();
        // Two replies produced.
        let (r1, n1) = decode_frame(&out).unwrap();
        let (r2, _) = decode_frame(&out[n1..]).unwrap();
        assert_eq!(r1.kind, NmType::Hello);
        assert_eq!(r2.err.unwrap().code, NmErrorCode::Locked);
    }
}
