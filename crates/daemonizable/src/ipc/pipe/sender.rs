//! The write half of the typed IPC pipe: [`Sender`].

use std::io::Write;
use std::marker::PhantomData;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

// `set_nonblocking` on the raw `interprocess` sender comes from this extension
// trait; it's used by the timeout-bounded send path (mirroring the receiver).
use interprocess::os::unix::unnamed_pipe::UnnamedPipeExt;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
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

    /// Like [`send_raw`](Self::send_raw), but bounded by `timeout` instead of
    /// blocking indefinitely. Used for the bootstrap payload during
    /// `spawn_daemon`: a child that passed the handshake and then wedged
    /// (SIGSTOP/ptrace) without draining the pipe would otherwise block the
    /// unbounded `write_all` forever once the kernel buffer fills, hanging the
    /// spawn and starving its failure-cleanup path. On expiry the underlying
    /// stream is left partially written and the sender must be abandoned (the
    /// failing spawn tears the daemon down regardless).
    pub(crate) fn send_raw_with_timeout(
        &mut self,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), PipeSendError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(PipeSendError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        self.sender.set_nonblocking(true)?;
        let timeout_at = Instant::now() + timeout;
        let len = bytes.len() as u32;
        write_all_with_timeout(&mut self.sender, &len.to_le_bytes(), timeout_at)?;
        write_all_with_timeout(&mut self.sender, bytes, timeout_at)?;
        Ok(())
    }

    fn write_length_prefixed(&mut self, bytes: &[u8]) -> Result<(), PipeSendError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(PipeSendError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        // Reset to blocking in case a prior timeout-bounded send left the fd
        // nonblocking (mirrors `Receiver::read_length_prefixed`).
        self.sender.set_nonblocking(false)?;
        let len = bytes.len() as u32;
        self.sender.write_all(&len.to_le_bytes())?;
        self.sender.write_all(bytes)?;
        Ok(())
    }
}

fn write_all_with_timeout<W: Write + AsFd>(
    writer: &mut W,
    buf: &[u8],
    timeout_at: Instant,
) -> Result<(), PipeSendError> {
    // `PollTimeout` holds milliseconds in a `u16`, so a single `poll` call can
    // wait at most ~65.5s; the impl loops across windows up to the real
    // deadline. `u16::MAX` is the production window; tests pass a small one to
    // drive the multi-window path without a 65s wait.
    write_all_with_timeout_impl(writer, buf, timeout_at, u16::MAX)
}

fn write_all_with_timeout_impl<W: Write + AsFd>(
    writer: &mut W,
    buf: &[u8],
    timeout_at: Instant,
    max_poll_window_ms: u16,
) -> Result<(), PipeSendError> {
    let mut bytes_written = 0;
    while bytes_written < buf.len() {
        match writer.write(&buf[bytes_written..]) {
            // A pipe write only reports 0 when it can make no progress and
            // won't be able to; treat it as a broken stream rather than spin.
            Ok(0) => {
                return Err(PipeSendError::Io(std::io::Error::from(
                    std::io::ErrorKind::WriteZero,
                )));
            }
            Ok(n) => bytes_written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Wait for buffer space using poll() instead of busy-waiting.
                loop {
                    let remaining = timeout_at.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(PipeSendError::Timeout);
                    }

                    let poll_fd = PollFd::new(writer.as_fd(), PollFlags::POLLOUT);
                    // Cap each poll wait at `max_poll_window_ms`. When `remaining`
                    // exceeds that window a single `poll` expires before the real
                    // deadline — so on expiry we loop back to the
                    // `remaining.is_zero()` check above rather than erroring, which
                    // would cut any timeout longer than one window short.
                    let timeout_ms: u16 = remaining
                        .as_millis()
                        .try_into()
                        .unwrap_or(max_poll_window_ms)
                        .min(max_poll_window_ms);
                    match poll(&mut [poll_fd], PollTimeout::from(timeout_ms)) {
                        Ok(0) => continue, // poll window expired; re-check the real deadline
                        Ok(_) => break,    // Space available, retry write
                        Err(nix::errno::Errno::EINTR) => continue, // Interrupted, retry poll
                        Err(e) => return Err(PipeSendError::Io(e.into())),
                    }
                }
            }
            Err(e) => return Err(PipeSendError::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::os::unix::unnamed_pipe::UnnamedPipeExt;
    use std::io::Read;

    /// Write to a nonblocking pipe sender until its kernel buffer is completely
    /// full, so the next write of any size blocks on `WouldBlock`. Fills in
    /// large chunks, then tops off one byte at a time so zero bytes remain (a
    /// pipe write of ≤ PIPE_BUF is atomic, so a chunk-only fill could leave a
    /// few bytes free and let a small write sneak through).
    fn fill_pipe_buffer(sender: &mut interprocess::unnamed_pipe::Sender) {
        let chunk = [0u8; 4096];
        loop {
            match sender.write(&chunk) {
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("unexpected error filling pipe: {e:?}"),
            }
        }
        loop {
            match sender.write(&[0u8]) {
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("unexpected error topping off pipe: {e:?}"),
            }
        }
    }

    // Regression test for the poll-window clamp: a send whose deadline is longer
    // than a single poll window must not be cut short when a window expires.
    // Driven with a tiny window so we don't need a 65s wait; production uses
    // u16::MAX. The buffer starts full and a reader frees space after several
    // windows; the write must wait for it rather than erroring early.
    #[test]
    fn write_all_with_timeout_completes_when_reader_drains_after_several_windows() {
        use std::thread;

        let (mut raw_sender, mut raw_recver) = interprocess::unnamed_pipe::pipe().unwrap();
        raw_sender.set_nonblocking(true).unwrap();
        fill_pipe_buffer(&mut raw_sender);

        let reader = thread::spawn(move || {
            // Free space after ~3 windows of the 20ms cap below.
            thread::sleep(Duration::from_millis(60));
            let mut scratch = vec![0u8; 256 * 1024];
            let _ = raw_recver.read(&mut scratch);
            raw_recver // keep the read end open until the write completes
        });

        write_all_with_timeout_impl(
            &mut raw_sender,
            &[1u8, 2, 3, 4],
            Instant::now() + Duration::from_secs(5),
            /* max_poll_window_ms */ 20,
        )
        .expect("space freed after several poll windows must let the write complete");
        drop(reader.join().unwrap());
    }

    // The wait must run until the *real* deadline, not stop after one poll
    // window. The buffer stays full (no reader) and the read end is held open so
    // this is a timeout, not an EPIPE. With a 20ms window and a 120ms deadline a
    // one-window bail would return after ~20ms.
    #[test]
    fn write_all_with_timeout_waits_full_deadline_not_one_poll_window() {
        let (mut raw_sender, _raw_recver) = interprocess::unnamed_pipe::pipe().unwrap();
        raw_sender.set_nonblocking(true).unwrap();
        fill_pipe_buffer(&mut raw_sender);

        let start = Instant::now();
        let err = write_all_with_timeout_impl(
            &mut raw_sender,
            &[1u8, 2, 3, 4],
            start + Duration::from_millis(120),
            /* max_poll_window_ms */ 20,
        )
        .expect_err("buffer full with no reader must time out");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(90),
            "timed out after {elapsed:?}; should have waited the full deadline, not one poll window"
        );
        assert!(
            matches!(err, PipeSendError::Timeout),
            "expected a timeout error, got: {err:?}"
        );
    }
}
