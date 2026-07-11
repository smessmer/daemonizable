//! The read half of the typed IPC pipe: [`Receiver`], plus the
//! timeout-bounded read machinery it uses to enforce deadlines without
//! busy-waiting.

use std::io::Read;
use std::marker::PhantomData;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

// `set_nonblocking` on the raw `interprocess` recver comes from this extension
// trait; it's used both by [`Receiver`]'s timeout receives and by the tests
// that drive the poll loop directly.
use interprocess::os::unix::unnamed_pipe::UnnamedPipeExt;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use serde::{Serialize, de::DeserializeOwned};

use super::MAX_MESSAGE_SIZE;
use crate::ipc::error::PipeRecvError;

pub struct Receiver<T>
where
    T: Serialize + DeserializeOwned,
{
    recver: interprocess::unnamed_pipe::Recver,
    _p: PhantomData<T>,
}

impl<T> Receiver<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(super) fn new(recver: interprocess::unnamed_pipe::Recver) -> Self {
        Self {
            recver,
            _p: PhantomData,
        }
    }

    /// Construct a typed `Receiver` from a raw owned file descriptor that the
    /// caller has verified is the read end of a pipe inherited across `execve`.
    /// Used by the fork+exec daemon child to rebuild its `RpcServer`.
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self::new(interprocess::unnamed_pipe::Recver::from(fd))
    }

    /// Surrender the typed wrapper and recover the underlying owned file
    /// descriptor. Used to `dup2` the fd onto a fixed slot in a child process.
    pub fn into_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.recver)
    }

    pub fn recv(&mut self) -> Result<T, PipeRecvError> {
        let buf = self.read_length_prefixed()?;
        Ok(postcard::from_bytes(&buf)?)
    }

    /// Receive a length-prefixed raw byte payload without postcard decoding,
    /// bounded by `timeout`. Used by the parent CLI to bound how long it'll
    /// wait for the daemon's build-id handshake — without a timeout,
    /// exec'ing a binary that opens fd 4 but never writes (or hangs) would
    /// hang the CLI forever.
    pub(crate) fn recv_raw_timeout(&mut self, timeout: Duration) -> Result<Vec<u8>, PipeRecvError> {
        self.recver.set_nonblocking(true)?;
        let timeout_at = Instant::now() + timeout;

        let mut len_bytes = [0u8; 4];
        read_exact_with_timeout(&mut self.recver, &mut len_bytes, timeout_at)?;

        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(PipeRecvError::MessageTooLarge {
                size: len,
                max: MAX_MESSAGE_SIZE,
            });
        }
        let mut buf = vec![0u8; len];
        read_exact_with_timeout(&mut self.recver, &mut buf, timeout_at)?;

        Ok(buf)
    }

    fn read_length_prefixed(&mut self) -> Result<Vec<u8>, PipeRecvError> {
        self.recver.set_nonblocking(false)?;
        let mut len_bytes = [0u8; 4];
        self.recver
            .read_exact(&mut len_bytes)
            .map_err(normalize_blocking_read_err)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(PipeRecvError::MessageTooLarge {
                size: len,
                max: MAX_MESSAGE_SIZE,
            });
        }
        let mut buf = vec![0u8; len];
        self.recver
            .read_exact(&mut buf)
            .map_err(normalize_blocking_read_err)?;
        Ok(buf)
    }

    // TODO A mid-frame error silently desynchronizes the stream: this (and
    //   `recv_raw_timeout`) consumes wire bytes incrementally but keeps no
    //   state across calls, so a `Timeout` that fires after the 4-byte length
    //   prefix (or part of the payload) was already read — deterministically
    //   constructible whenever the sender pauses between prefix and payload —
    //   leaves the next call interpreting payload bytes as a new length
    //   prefix: it can postcard-decode garbage into a syntactically valid but
    //   WRONG value returned as Ok, or fail with spurious
    //   MessageTooLarge/Decode, and every later message stays misframed. The
    //   recv-side MessageTooLarge return has the same problem (prefix
    //   consumed, declared payload left unread). No in-tree caller retries
    //   after these errors (all treat them as terminal), but the public
    //   timeout API invites poll-with-short-timeout retry loops. Fix,
    //   preferred: poison the Receiver on any mid-frame Timeout /
    //   MessageTooLarge (a `poisoned: bool` field checked at the top of every
    //   recv; add a dedicated PipeRecvError::Desynchronized variant) — a
    //   zero-bytes-read Timeout is clean and must NOT poison, so retries of
    //   an idle channel keep working. Alternative: keep the partial frame
    //   (length + buffer + offset) as Receiver state so a retry resumes the
    //   same frame. At minimum: document on recv_timeout, recv_response and
    //   the Timeout/MessageTooLarge variants that the connection must be
    //   abandoned after these errors.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<T, PipeRecvError>
    where
        T: Send,
    {
        self.recver.set_nonblocking(true)?;
        let timeout_at = Instant::now() + timeout;

        let mut len_bytes = [0u8; 4];
        read_exact_with_timeout(&mut self.recver, &mut len_bytes, timeout_at)?;

        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(PipeRecvError::MessageTooLarge {
                size: len,
                max: MAX_MESSAGE_SIZE,
            });
        }
        let mut buf = vec![0u8; len];
        read_exact_with_timeout(&mut self.recver, &mut buf, timeout_at)?;

        Ok(postcard::from_bytes(&buf)?)
    }
}

/// `read_exact` on a blocking pipe reports a closed write end as
/// `UnexpectedEof`. Normalize that into [`PipeRecvError::SenderClosed`] so
/// EOF has a single variant across blocking and timeout-bounded receives
/// (the timeout path detects EOF itself via `read() == Ok(0)`).
fn normalize_blocking_read_err(e: std::io::Error) -> PipeRecvError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        PipeRecvError::SenderClosed
    } else {
        PipeRecvError::Io(e)
    }
}

fn read_exact_with_timeout<R: Read + AsFd>(
    reader: &mut R,
    buf: &mut [u8],
    timeout_at: Instant,
) -> Result<(), PipeRecvError> {
    // `PollTimeout` holds milliseconds in a `u16`, so a single `poll` call can
    // wait at most ~65.5s; the impl loops across windows up to the real
    // deadline. `u16::MAX` is the production window; tests pass a small one to
    // drive the multi-window path without a 65s wait.
    read_exact_with_timeout_impl(reader, buf, timeout_at, u16::MAX)
}

fn read_exact_with_timeout_impl<R: Read + AsFd>(
    reader: &mut R,
    buf: &mut [u8],
    timeout_at: Instant,
    max_poll_window_ms: u16,
) -> Result<(), PipeRecvError> {
    let mut bytes_read = 0;
    while bytes_read < buf.len() {
        match reader.read(&mut buf[bytes_read..]) {
            Ok(0) => return Err(PipeRecvError::SenderClosed),
            Ok(n) => bytes_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Wait for data using poll() instead of busy-waiting
                loop {
                    let remaining = timeout_at.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(PipeRecvError::Timeout);
                    }

                    let poll_fd = PollFd::new(reader.as_fd(), PollFlags::POLLIN);
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
                        Ok(_) => break,    // Data available, retry read
                        Err(nix::errno::Errno::EINTR) => continue, // Interrupted, retry poll
                        Err(e) => return Err(PipeRecvError::Io(e.into())),
                    }
                }
            }
            Err(e) => return Err(PipeRecvError::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the poll-window clamp: a read whose deadline is longer
    // than a single poll window must not be cut short when the window expires.
    // Driven with a tiny window so we don't need a 65s wait; the production path
    // uses u16::MAX. With the old `Ok(0) => bail!` this failed after one window.
    #[test]
    fn read_exact_with_timeout_receives_data_spanning_multiple_poll_windows() {
        use std::io::Write;
        use std::thread;

        // Drive the poll loop against a raw pipe so we can write unframed bytes
        // directly (the typed `Sender::send` would length-prefix them).
        let (mut raw_sender, mut raw_recver) = interprocess::unnamed_pipe::pipe().unwrap();
        raw_recver.set_nonblocking(true).unwrap();

        let writer = thread::spawn(move || {
            // Arrives after ~3 windows of the 20ms cap below.
            thread::sleep(Duration::from_millis(60));
            raw_sender.write_all(&[1u8, 2, 3, 4]).unwrap();
            raw_sender // keep the send end open until the read completes
        });

        let mut buf = [0u8; 4];
        read_exact_with_timeout_impl(
            &mut raw_recver,
            &mut buf,
            Instant::now() + Duration::from_secs(5),
            /* max_poll_window_ms */ 20,
        )
        .expect("data arriving after several poll windows must still be read");
        assert_eq!([1u8, 2, 3, 4], buf);
        drop(writer.join().unwrap());
    }

    // The wait must run until the *real* deadline, not stop after one poll
    // window. No data ever arrives; with a 20ms window and a 120ms deadline the
    // buggy `Ok(0) => bail!` would return after ~20ms.
    #[test]
    fn read_exact_with_timeout_waits_full_deadline_not_one_poll_window() {
        let (sender, mut recver) = crate::ipc::pipe::pipe::<u32>().unwrap();
        recver.recver.set_nonblocking(true).unwrap();

        let mut buf = [0u8; 4];
        let start = Instant::now();
        let err = read_exact_with_timeout_impl(
            &mut recver.recver,
            &mut buf,
            start + Duration::from_millis(120),
            /* max_poll_window_ms */ 20,
        )
        .expect_err("no data was sent, so this must time out");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(90),
            "timed out after {elapsed:?}; should have waited the full deadline, not one poll window"
        );
        assert!(
            matches!(err, PipeRecvError::Timeout),
            "expected a timeout error, got: {err:?}"
        );
        drop(sender); // keep the send end open until here so this is a timeout, not EOF
    }
}
