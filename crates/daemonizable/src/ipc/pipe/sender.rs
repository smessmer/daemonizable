//! The write half of the typed IPC channel: [`Sender`].

use std::io::Write;
use std::marker::PhantomData;
#[cfg(test)]
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};

use super::MAX_MESSAGE_SIZE;
use crate::ipc::error::PipeSendError;

pub struct Sender<T>
where
    T: Serialize + DeserializeOwned,
{
    sender: UnixStream,
    _p: PhantomData<T>,
}

impl<T> Sender<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(super) fn new(sender: UnixStream) -> Self {
        Self {
            sender,
            _p: PhantomData,
        }
    }

    /// Surrender the typed wrapper and recover the underlying owned file
    /// descriptor. Test-only (used to inspect the raw fd's flags).
    #[cfg(test)]
    pub fn into_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.sender)
    }

    pub fn send(&mut self, data: &T) -> Result<(), PipeSendError> {
        let bytes = postcard::to_stdvec(data)?;
        self.write_length_prefixed(&bytes)
    }

    /// Send a length-prefixed raw byte payload without postcard encoding.
    /// Used for the build-id handshake before typed RPC begins: encoding the
    /// handshake via postcard would defeat its purpose of validating that
    /// parent and child agree on the postcard schema.
    pub(crate) fn send_raw(&mut self, bytes: &[u8]) -> Result<(), PipeSendError> {
        self.write_length_prefixed(bytes)
    }

    fn write_length_prefixed(&mut self, bytes: &[u8]) -> Result<(), PipeSendError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(PipeSendError::MessageTooLarge {
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
        // error. std's socket writes carry `MSG_NOSIGNAL` (Linux) /
        // `SO_NOSIGPIPE` (Apple), so a write to a closed peer returns `EPIPE`
        // rather than raising `SIGPIPE`, even in a process that reset SIGPIPE
        // to its default disposition.
        let len = bytes.len() as u32;
        self.sender.write_all(&len.to_le_bytes())?;
        self.sender.write_all(bytes)?;
        Ok(())
    }
}
