//! The write half of the typed IPC pipe: [`Sender`].

use std::io::Write;
use std::marker::PhantomData;
use std::os::fd::OwnedFd;

use serde::{Serialize, de::DeserializeOwned};

use super::MAX_MESSAGE_SIZE;
use crate::ipc::error::PipeSendError;

pub struct Sender<T>
where
    T: Serialize + DeserializeOwned,
{
    sender: interprocess::unnamed_pipe::Sender,
    _p: PhantomData<T>,
}

impl<T> Sender<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(super) fn new(sender: interprocess::unnamed_pipe::Sender) -> Self {
        Self {
            sender,
            _p: PhantomData,
        }
    }

    /// Construct a typed `Sender` from a raw owned file descriptor that the
    /// caller has verified is the write end of a pipe inherited across `execve`.
    /// Used by the fork+exec daemon child to rebuild its `RpcServer`.
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self::new(interprocess::unnamed_pipe::Sender::from(fd))
    }

    /// Surrender the typed wrapper and recover the underlying owned file
    /// descriptor. Used to `dup2` the fd onto a fixed slot in a child process.
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
        let len = bytes.len() as u32;
        self.sender.write_all(&len.to_le_bytes())?;
        self.sender.write_all(bytes)?;
        Ok(())
    }
}
