//! The read half of the typed IPC channel: [`Receiver`], plus the
//! timeout-bounded read machinery it uses to enforce deadlines without
//! busy-waiting.

use std::io::Read;
use std::marker::PhantomData;
#[cfg(test)]
use std::os::fd::OwnedFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{MsgFlags, recv};
use serde::{Serialize, de::DeserializeOwned};

use super::MAX_MESSAGE_SIZE;
use crate::ipc::error::ChannelRecvError;

pub struct Receiver<T>
where
    T: Serialize + DeserializeOwned,
{
    recver: UnixStream,
    /// Set once a receive consumes part of a message frame and then fails,
    /// leaving the stream desynchronized (see [`ChannelRecvError::Desynchronized`]).
    /// Once set, every receive fails fast without touching the socket.
    poisoned: bool,
    _p: PhantomData<T>,
}

impl<T> Receiver<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(super) fn new(recver: UnixStream) -> Self {
        Self {
            recver,
            poisoned: false,
            _p: PhantomData,
        }
    }

    /// Surrender the typed wrapper and recover the underlying owned file
    /// descriptor. Test-only (used to inspect the raw fd's flags).
    #[cfg(test)]
    pub fn into_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.recver)
    }

    pub fn recv(&mut self) -> Result<T, ChannelRecvError> {
        let buf = self.read_length_prefixed()?;
        // A decode failure here does NOT poison: the whole frame was read off
        // the wire correctly, so the stream is still synchronized.
        Ok(postcard::from_bytes(&buf)?)
    }

    /// Receive a length-prefixed raw byte payload without postcard decoding,
    /// bounded by `timeout`. Used by the parent CLI to bound how long it'll
    /// wait for the daemon's build-id handshake — without a timeout,
    /// exec'ing a binary that opens the channel fd but never writes (or hangs)
    /// would hang the CLI forever.
    ///
    /// If a `Timeout` fires after part of a frame was already consumed, or the
    /// length prefix declares an oversized payload that is then left unread, the
    /// stream is desynchronized: the `Receiver` is poisoned and all subsequent
    /// receives fail with [`ChannelRecvError::Desynchronized`]. A clean idle
    /// timeout (nothing consumed) does not poison, so polling an idle channel
    /// with short timeouts keeps working.
    pub(crate) fn recv_raw_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, ChannelRecvError> {
        if self.poisoned {
            return Err(ChannelRecvError::Desynchronized);
        }
        let timeout_at = deadline_from(timeout);

        // Length prefix. A timeout that consumed 0 bytes is a clean idle poll
        // and must not poison; a partial prefix (1–3 bytes) leaves the wire
        // mid-frame and must.
        let mut len_bytes = [0u8; 4];
        let mut prefix_read = 0;
        if let Err(err) = read_exact_with_timeout(
            self.recver.as_fd(),
            &mut len_bytes,
            timeout_at,
            &mut prefix_read,
        ) {
            if matches!(err, ChannelRecvError::Timeout) && prefix_read > 0 {
                self.poisoned = true;
            }
            return Err(err);
        }

        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_SIZE {
            // The prefix is consumed but the declared payload is still on the
            // wire; a later read would misframe it. Poison.
            self.poisoned = true;
            return Err(ChannelRecvError::MessageTooLarge {
                size: len,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Payload. The prefix was fully consumed, so any timeout here is
        // mid-frame and poisons.
        let mut buf = vec![0u8; len];
        let mut payload_read = 0;
        if let Err(err) =
            read_exact_with_timeout(self.recver.as_fd(), &mut buf, timeout_at, &mut payload_read)
        {
            if matches!(err, ChannelRecvError::Timeout) {
                self.poisoned = true;
            }
            return Err(err);
        }

        Ok(buf)
    }

    /// Receive one postcard-decoded message, bounded by `timeout`. Framing (and
    /// its poisoning contract) is shared with [`recv_raw_timeout`](Self::recv_raw_timeout);
    /// this only adds the decode step, which never poisons.
    ///
    /// An extremely large `timeout` (e.g. `Duration::MAX`) is clamped rather
    /// than panicking on deadline overflow; for a genuinely unbounded wait, use
    /// the blocking [`recv`](Self::recv) instead.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<T, ChannelRecvError>
    where
        T: Send,
    {
        let buf = self.recv_raw_timeout(timeout)?;
        Ok(postcard::from_bytes(&buf)?)
    }

    fn read_length_prefixed(&mut self) -> Result<Vec<u8>, ChannelRecvError> {
        if self.poisoned {
            return Err(ChannelRecvError::Desynchronized);
        }
        // The socket is blocking (never toggled — see `Receiver`'s timeout
        // path), so `read_exact` blocks until the frame arrives or the peer
        // closes.
        let mut len_bytes = [0u8; 4];
        self.recver
            .read_exact(&mut len_bytes)
            .map_err(normalize_blocking_read_err)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_SIZE {
            // Prefix consumed, oversized payload left unread → desynced, same as
            // the timeout path. (A blocking read can't time out mid-frame; a
            // truncated frame surfaces as SenderClosed, which is terminal EOF
            // and needs no poisoning.)
            self.poisoned = true;
            return Err(ChannelRecvError::MessageTooLarge {
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
}

/// Upper bound on the deadline a caller-supplied timeout can produce, used only
/// when the requested `Duration` would overflow `Instant + Duration`. ~30 years
/// is "effectively forever" for a receive deadline yet far inside every
/// platform's `Instant` range, so adding it to `Instant::now()` can't itself
/// overflow in practice.
const MAX_DEADLINE_FROM_NOW: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 30);

/// Turn a caller-supplied timeout into an absolute deadline without panicking.
///
/// `Instant + Duration` panics on overflow, and `recv_timeout` /
/// `recv_response` take an arbitrary `Duration` from the caller — a very large
/// one (e.g. `Duration::MAX`, sometimes used as a stand-in for "wait a long
/// time") would otherwise crash the process. We saturate instead: a timeout
/// that would overflow is clamped to [`MAX_DEADLINE_FROM_NOW`] out. (For a
/// genuinely unbounded wait, use the blocking `recv` / `recv_response_blocking`
/// path, which has no deadline at all.)
fn deadline_from(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .or_else(|| now.checked_add(MAX_DEADLINE_FROM_NOW))
        // `now + MAX_DEADLINE_FROM_NOW` can't overflow in practice; the final
        // `unwrap_or(now)` (an immediate deadline) keeps this total and
        // panic-free even if some exotic platform disagreed.
        .unwrap_or(now)
}

/// `read_exact` on a blocking socket reports a closed peer as `UnexpectedEof`
/// (a clean `shutdown`/close with the read queue drained) or as
/// `ConnectionReset` (the peer was killed/closed while its OWN receive queue
/// still held unread bytes — an `AF_UNIX` behavior pipes never exhibit).
/// Normalize both into [`ChannelRecvError::SenderClosed`] so EOF has a single
/// variant across blocking and timeout-bounded receives (the timeout path
/// detects the same conditions via `recv() == Ok(0)` / `ECONNRESET`).
fn normalize_blocking_read_err(e: std::io::Error) -> ChannelRecvError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => {
            ChannelRecvError::SenderClosed
        }
        _ => ChannelRecvError::Io(e),
    }
}

/// Reads exactly `buf.len()` bytes or fails, bounded by `timeout_at`. `*bytes_read`
/// is updated with how many bytes were consumed; on a `Timeout` the caller
/// inspects it to tell a clean idle timeout (0) from a mid-frame one (>0).
///
/// The socket is left BLOCKING throughout: readiness is awaited with `poll`,
/// and the actual read uses `recv(MSG_DONTWAIT)` so it never blocks even on a
/// spurious poll wake-up. This deliberately avoids toggling the description's
/// `O_NONBLOCK` — the sender may share this same open file description (they are
/// two ends... two clones of one socket once the channel is collapsed to a
/// single fd), and flipping `O_NONBLOCK` would corrupt the sender's blocking
/// writes.
fn read_exact_with_timeout(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    timeout_at: Instant,
    bytes_read: &mut usize,
) -> Result<(), ChannelRecvError> {
    // `PollTimeout` holds milliseconds in a `u16`, so a single `poll` call can
    // wait at most ~65.5s; the impl loops across windows up to the real
    // deadline. `u16::MAX` is the production window; tests pass a small one to
    // drive the multi-window path without a 65s wait.
    read_exact_with_timeout_impl(fd, buf, timeout_at, u16::MAX, bytes_read)
}

fn read_exact_with_timeout_impl(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    timeout_at: Instant,
    max_poll_window_ms: u16,
    bytes_read: &mut usize,
) -> Result<(), ChannelRecvError> {
    *bytes_read = 0;
    while *bytes_read < buf.len() {
        // Read without blocking first. `MSG_DONTWAIT` makes this recv
        // non-blocking regardless of the socket's (blocking) mode. Reading
        // before polling means data already waiting is consumed even when the
        // deadline has already passed (e.g. a `Duration::ZERO` timeout with a
        // ready frame).
        match recv(
            fd.as_raw_fd(),
            &mut buf[*bytes_read..],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => return Err(ChannelRecvError::SenderClosed),
            Ok(n) => {
                *bytes_read += n;
                continue;
            }
            // Nothing available yet → fall through to poll below.
            Err(Errno::EAGAIN) => {}
            Err(Errno::EINTR) => continue,
            // Peer died with unread data queued on its side — treat as EOF.
            Err(Errno::ECONNRESET) => return Err(ChannelRecvError::SenderClosed),
            Err(e) => return Err(ChannelRecvError::Io(std::io::Error::from(e))),
        }

        // Not ready: wait for readiness using poll() instead of busy-waiting.
        let remaining = timeout_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ChannelRecvError::Timeout);
        }
        let poll_fd = PollFd::new(fd, PollFlags::POLLIN);
        // Cap each poll wait at `max_poll_window_ms`. When `remaining` exceeds
        // that window a single `poll` expires before the real deadline — so on
        // expiry we loop back (retry the recv, then re-check the real deadline)
        // rather than erroring, which would cut any timeout longer than one
        // window short.
        let timeout_ms: u16 = remaining
            .as_millis()
            .try_into()
            .unwrap_or(max_poll_window_ms)
            .min(max_poll_window_ms);
        match poll(&mut [poll_fd], PollTimeout::from(timeout_ms)) {
            Ok(_) => continue,             // readable, or window expired — retry the recv
            Err(Errno::EINTR) => continue, // interrupted, retry
            Err(e) => return Err(ChannelRecvError::Io(e.into())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the deadline-overflow guard: `Instant::now() + timeout`
    // panics when `timeout` is large enough to overflow `Instant` (e.g.
    // `Duration::MAX`, a plausible "wait a long time" stand-in). `deadline_from`
    // must clamp instead of panicking. Data is already available, so the receive
    // returns immediately after computing the (clamped) deadline — exercising the
    // previously-panicking line without actually waiting.
    #[test]
    fn recv_timeout_with_overflowing_duration_does_not_panic() {
        let (mut sender, mut recver) = crate::ipc::channel::channel_pair::<u32>().unwrap();
        sender.send(&7).unwrap();
        assert_eq!(
            recver.recv_timeout(Duration::MAX).unwrap(),
            7,
            "a Duration that overflows the deadline must be clamped, not panic"
        );
    }

    // `deadline_from` is total and never panics, even on `Duration::MAX`, and a
    // clamped deadline is still in the future (so it doesn't spuriously time out
    // immediately).
    #[test]
    fn deadline_from_clamps_instead_of_overflowing() {
        let before = Instant::now();
        let clamped = deadline_from(Duration::MAX);
        assert!(
            clamped > before,
            "a clamped deadline must still be in the future"
        );
        // A normal timeout is unaffected: the deadline is ~`timeout` out.
        let normal = deadline_from(Duration::from_secs(1));
        assert!(normal > Instant::now());
    }

    // Regression test for the poll-window clamp: a read whose deadline is longer
    // than a single poll window must not be cut short when the window expires.
    // Driven with a tiny window so we don't need a 65s wait; the production path
    // uses u16::MAX. With the old `Ok(0) => bail!` this failed after one window.
    #[test]
    fn read_exact_with_timeout_receives_data_spanning_multiple_poll_windows() {
        use std::io::Write;
        use std::thread;

        // Drive the poll loop against a raw socketpair so we can write unframed
        // bytes directly (the typed `Sender::send` would length-prefix them).
        let (mut raw_sender, raw_recver) = UnixStream::pair().unwrap();

        let writer = thread::spawn(move || {
            // Arrives after ~3 windows of the 20ms cap below.
            thread::sleep(Duration::from_millis(60));
            raw_sender.write_all(&[1u8, 2, 3, 4]).unwrap();
            raw_sender // keep the send end open until the read completes
        });

        let mut buf = [0u8; 4];
        let mut bytes_read = 0;
        read_exact_with_timeout_impl(
            raw_recver.as_fd(),
            &mut buf,
            Instant::now() + Duration::from_secs(5),
            /* max_poll_window_ms */ 20,
            &mut bytes_read,
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
        let (sender, recver) = UnixStream::pair().unwrap();

        let mut buf = [0u8; 4];
        let mut bytes_read = 0;
        let start = Instant::now();
        let err = read_exact_with_timeout_impl(
            recver.as_fd(),
            &mut buf,
            start + Duration::from_millis(120),
            /* max_poll_window_ms */ 20,
            &mut bytes_read,
        )
        .expect_err("no data was sent, so this must time out");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(90),
            "timed out after {elapsed:?}; should have waited the full deadline, not one poll window"
        );
        assert!(
            matches!(err, ChannelRecvError::Timeout),
            "expected a timeout error, got: {err:?}"
        );
        drop(sender); // keep the send end open until here so this is a timeout, not EOF
    }
}
