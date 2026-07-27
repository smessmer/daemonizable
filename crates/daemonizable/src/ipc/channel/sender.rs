//! The write half of the typed IPC channel: [`Sender`].

use std::io::Write;
use std::marker::PhantomData;
#[cfg(test)]
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::Serialize;

use super::MAX_MESSAGE_SIZE;
use crate::ipc::error::ChannelSendError;

pub(in crate::ipc) struct Sender<T>
where
    T: Serialize,
{
    sender: UnixStream,
    /// Set once a send fails after (possibly partially) writing a frame,
    /// leaving the wire mid-frame on the send side (see
    /// [`ChannelSendError::Desynchronized`]). Once set, every send fails fast
    /// without touching the socket — a retried send would otherwise append a
    /// fresh length prefix that the peer consumes as leftover payload bytes,
    /// silently desynchronizing all subsequent traffic. Mirrors the receiver's
    /// poison flag.
    poisoned: bool,
    _p: PhantomData<T>,
}

impl<T> std::fmt::Debug for Sender<T>
where
    T: Serialize,
{
    // Manual impl (like `Daemonizer`'s) so no `T: Debug` bound leaks into the
    // API via the `PhantomData`. The socket's own Debug shows the fd numbers,
    // which is the useful part when debugging a daemon channel.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("sender", &self.sender)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<T> Sender<T>
where
    T: Serialize,
{
    pub(super) fn new(sender: UnixStream) -> Self {
        Self {
            sender,
            poisoned: false,
            _p: PhantomData,
        }
    }

    /// Surrender the typed wrapper and recover the underlying owned file
    /// descriptor. Test-only (used by the parent module's tests to inspect the
    /// raw fd's flags).
    #[cfg(test)]
    pub(super) fn into_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.sender)
    }

    /// Send one typed, postcard-encoded, length-prefixed message.
    ///
    /// If a previous send failed mid-frame, the sender is poisoned and this
    /// returns [`ChannelSendError::Desynchronized`] without touching the
    /// socket — abandon the endpoint (see the `poisoned` field doc).
    pub fn send(&mut self, data: &T) -> Result<(), ChannelSendError> {
        let bytes = postcard::to_stdvec(data)?;
        self.write_length_prefixed(&bytes)
    }

    /// Send a length-prefixed raw byte payload without postcard encoding.
    /// Used for the build-id handshake before typed RPC begins: encoding the
    /// handshake via postcard would defeat its purpose of validating that
    /// parent and child agree on the postcard schema.
    pub(in crate::ipc) fn send_raw(&mut self, bytes: &[u8]) -> Result<(), ChannelSendError> {
        self.write_length_prefixed(bytes)
    }

    /// Write raw, UNFRAMED bytes at the head of the stream — used only by the
    /// parent to pre-queue the stage-identity tokens before the framed RPC
    /// begins. The daemon's dispatch consumes these raw (they are not
    /// length-prefixed), then reads framed messages after. Must be called
    /// before any `send`/`send_raw` so the tokens lead the stream.
    pub(in crate::ipc) fn write_prelude(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.sender.write_all(bytes)
    }

    /// The framing shared by [`send`](Self::send) and
    /// [`send_raw`](Self::send_raw): `[4-byte LE length] [payload]`, with the
    /// sender-side poison contract documented on the `poisoned` field.
    fn write_length_prefixed(&mut self, bytes: &[u8]) -> Result<(), ChannelSendError> {
        // Poison check first: a desynchronized wire is terminal, and reporting
        // it dominates every other outcome (even an oversized payload).
        if self.poisoned {
            return Err(ChannelSendError::Desynchronized);
        }
        if bytes.len() > MAX_MESSAGE_SIZE {
            // Nothing was written, so the wire is still synchronized — no
            // poison, mirroring the receiver's clean-idle-timeout rule.
            return Err(ChannelSendError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        // The socket is always blocking — it is created blocking and nothing
        // ever switches it to non-blocking (the receiver's timeout path polls
        // and reads with `MSG_DONTWAIT` rather than toggling the shared
        // description's `O_NONBLOCK`; see `Receiver`). So `write_all` can't
        // return `WouldBlock` mid-frame under backpressure — a full send blocks
        // until the peer drains, and a broken pipe surfaces as a terminal Io
        // error. (For why a write to a closed peer surfaces as `EPIPE` rather
        // than a process-killing `SIGPIPE` — unconditionally, whatever the
        // process's SIGPIPE disposition — see the note on `channel_pair` in
        // `channel/mod.rs`; it is why the MSRV is 1.90.)
        //
        // Any error from either write poisons the sender: `write_all` gives no
        // way to observe how many bytes landed before the failure, so the wire
        // must be assumed mid-frame — a retried send would misframe (see the
        // `poisoned` field doc). Poisoning after a terminal EPIPE is harmless.
        let len = bytes.len() as u32;
        if let Err(err) = self
            .sender
            .write_all(&len.to_le_bytes())
            .and_then(|()| self.sender.write_all(bytes))
        {
            self.poisoned = true;
            return Err(ChannelSendError::Io(err));
        }
        Ok(())
    }
}
