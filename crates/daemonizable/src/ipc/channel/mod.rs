//! Typed, length-prefixed IPC channel primitive.
//!
//! [`endpoint_from_stream`] splits one `AF_UNIX` `SOCK_STREAM` socket into the
//! typed [`Sender`]/[`Receiver`] halves that drive it, and the two ends live in
//! their own modules: [`mod@sender`] owns the write side, [`mod@receiver`] the
//! read side (including the timeout-bounded read machinery). The socket fds are
//! `FD_CLOEXEC` so they don't leak across the fork+exec daemon spawn. Both ends
//! share the [`MAX_MESSAGE_SIZE`] wire-format cap defined here.

use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};

#[cfg(test)]
use super::error::ChannelCreateError;

mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

/// Maximum message size (1 MiB). Protects against DoS from malicious/buggy senders.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Create a new channel that can be used across forking for interprocess
/// communication.
///
/// Both ends are CLOEXEC so they're closed by the kernel during `execve`. The
/// fork+exec daemon spawn relies on this: only fds explicitly remapped via
/// `posix_spawn_file_actions` / `pre_exec` (which clear CLOEXEC as a side
/// effect of `dup2`) survive into the child.
///
/// # Closing the CLOEXEC race
///
/// CLOEXEC has to be established *atomically* with socket creation. Were it set
/// in a second step (`fcntl(F_SETFD)` after `socketpair()`), a concurrent thread
/// that `fork()`s — directly, or indirectly via `Command::spawn` — in the window
/// between the two calls would leak the still-inheritable socket fds into an
/// unrelated child. Symptoms range from leaked fds to EOF never being delivered
/// (the rightful owner can't detect the far end being dropped while a stranger
/// holds a duplicate of the peer end).
///
/// [`UnixStream::pair`] is std's `socketpair(AF_UNIX, SOCK_STREAM, 0)`. On
/// Linux/Android and every target with `SOCK_CLOEXEC`, std passes it so both
/// fds are created close-on-exec in the same syscall — the window doesn't exist
/// and the race is closed outright.
///
/// **macOS/iOS have no `SOCK_CLOEXEC`**, so std creates the pair and then sets
/// `FD_CLOEXEC` with a separate `ioctl(FIOCLEX)` on each fd, and the window
/// reopens. The standard workaround would be a process-wide fork lock that every
/// fork site honors (CPython's `subprocess` does this with
/// `_posixsubprocess._fork_lock`), but Rust's `std::process::Command` exposes no
/// such lock we could take, so on those targets we rely on a usage-level
/// invariant instead: no other thread may `fork()`/`Command::spawn()` while a
/// channel is being created. A running thread pool or async runtime is not
/// itself a problem — only an actual concurrent fork in the CLOEXEC-set window
/// is — but the simplest way to guarantee that is to spawn the daemon at
/// startup, before the process begins spawning other subprocesses. This is a
/// documented caller contract, not something the library can enforce at runtime
/// on those platforms. (std also sets `SO_NOSIGPIPE` on the socket on Apple
/// platforms, and passes `MSG_NOSIGNAL` on Linux writes, so a write to a closed
/// peer surfaces as an `EPIPE` error rather than a `SIGPIPE`.)
///
/// T: The type of the data that will be sent through the channel.
///
/// Test-only: production builds the full-duplex daemon channel through
/// [`endpoint_from_stream`]; this one-way constructor exists to exercise the
/// `Sender`/`Receiver` framing, timeout, and poison machinery in unit tests.
#[cfg(test)]
pub fn channel_pair<T>() -> Result<(Sender<T>, Receiver<T>), ChannelCreateError>
where
    T: Serialize + DeserializeOwned,
{
    // `UnixStream::pair()` returns two connected endpoints of one socketpair.
    // A `SOCK_STREAM` socketpair is full-duplex, but here we use it
    // unidirectionally: writes on the `Sender` end are read on the `Receiver`
    // end. (The daemon channel uses [`endpoint_from_stream`] to drive both
    // directions over a single fd; at this layer they are still one direction.)
    let (sender, recver) = UnixStream::pair().map_err(ChannelCreateError::CreateSocket)?;
    Ok((Sender::new(sender), Receiver::new(recver)))
}

/// Split one full-duplex socket endpoint into a typed [`Sender<S>`] and
/// [`Receiver<R>`] that both drive the SAME underlying socket. The two wrappers
/// hold `dup`-clones of one fd (`try_clone` → `F_DUPFD_CLOEXEC`, so the clone is
/// born `FD_CLOEXEC`), so one can be written while the other is read
/// concurrently — full duplex on a single fd.
///
/// EOF liveness note: because both wrappers reference the same open file
/// description, the peer observes EOF only once BOTH are dropped. The daemon
/// channel keeps exactly these two clones per side, so a dropped endpoint closes
/// the whole side and the peer's read unblocks.
///
/// `try_clone` (a `dup`) can fail (EMFILE/ENFILE); the caller maps the
/// `io::Error` into its own error type.
pub(crate) fn endpoint_from_stream<S, R>(
    stream: UnixStream,
) -> std::io::Result<(Sender<S>, Receiver<R>)>
where
    S: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned,
{
    let clone = stream.try_clone()?;
    Ok((Sender::new(clone), Receiver::new(stream)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::error::{ChannelRecvError, ChannelSendError};
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use serde::Deserialize;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn dropped_recver() {
        let (mut sender, recver) = channel_pair::<u32>().unwrap();
        drop(recver);
        // Writing to a socket whose peer has closed returns EPIPE (an error),
        // NOT a `SIGPIPE` that would kill the test process — std sets
        // `MSG_NOSIGNAL`/`SO_NOSIGPIPE` on the write path. That this test
        // returns rather than dying is itself the SIGPIPE-suppression check.
        assert!(sender.send(&42).is_err());
    }

    #[test]
    fn writing_after_peer_close_errors_without_sigpipe() {
        // Stronger form of `dropped_recver`: multiple sends after the peer
        // closed must each surface as an ordinary error and never raise
        // `SIGPIPE` (which would abort the process, failing the test loudly).
        // std uses `MSG_NOSIGNAL` (Linux) / `SO_NOSIGPIPE` (Apple), so this
        // holds even for a process that reset SIGPIPE to its default.
        let (mut sender, recver) = channel_pair::<u32>().unwrap();
        drop(recver);
        for _ in 0..4 {
            let err = sender.send(&1).unwrap_err();
            assert!(
                matches!(err, ChannelSendError::Io(_)),
                "expected an Io(BrokenPipe) error, got {err:?}"
            );
        }
    }

    #[test]
    fn channel_ends_have_cloexec_set() {
        // Both ends of channels created by our `channel_pair()` wrapper must have
        // FD_CLOEXEC set, so they're closed automatically by the kernel when
        // the daemon child execs the new binary. `UnixStream::pair()` sets this
        // atomically via `SOCK_CLOEXEC` on Linux (and with a separate
        // `ioctl(FIOCLEX)` on macOS/iOS); either way std guarantees CLOEXEC on
        // the fds it creates.
        let (sender, recver) = channel_pair::<u32>().unwrap();
        // Recover the owned fds so the descriptors stay valid for the fcntl
        // check below; they're closed when these `OwnedFd`s drop at the end.
        let sender_fd = sender.into_owned_fd();
        let recver_fd = recver.into_owned_fd();
        for (label, fd) in [("sender", sender_fd.as_fd()), ("recver", recver_fd.as_fd())] {
            let flags = FdFlag::from_bits_retain(
                fcntl(fd, FcntlArg::F_GETFD)
                    .unwrap_or_else(|e| panic!("fcntl(F_GETFD) failed for {label}: {e}")),
            );
            assert!(
                flags.contains(FdFlag::FD_CLOEXEC),
                "{label} end of channel is missing FD_CLOEXEC (flags={flags:?})",
            );
        }
    }

    mod recv {
        use super::*;

        #[test]
        fn primitive_u32() {
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            sender.send(&42).unwrap();
            assert_eq!(recver.recv().unwrap(), 42);
        }

        #[test]
        fn string() {
            let (mut sender, mut recver) = channel_pair::<String>().unwrap();
            sender.send(&"Hello, World!".to_string()).unwrap();
            assert_eq!(recver.recv().unwrap(), "Hello, World!");
        }

        #[test]
        fn custom_struct() {
            #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
            struct MyStruct {
                a: u32,
                b: String,
            }

            let (mut sender, mut recver) = channel_pair::<MyStruct>().unwrap();
            sender
                .send(&MyStruct {
                    a: 42,
                    b: "Hello, World!".to_string(),
                })
                .unwrap();
            assert_eq!(
                recver.recv().unwrap(),
                MyStruct {
                    a: 42,
                    b: "Hello, World!".to_string()
                }
            );
        }

        #[test]
        fn dropped_sender() {
            // Blocking-path EOF must be normalized to `SenderClosed`, not
            // surface as the raw `Io(UnexpectedEof)` that `read_exact` reports.
            let (sender, mut recver) = channel_pair::<u32>().unwrap();
            drop(sender);
            let error = recver.recv().unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::SenderClosed),
                "Unexpected error: {error:?}",
            );
        }

        // On Linux, closing an AF_UNIX stream socket while unread bytes remain
        // in ITS receive queue makes the peer's next read fail with
        // `ECONNRESET` rather than a clean EOF — a case pipes never produced.
        // The blocking receive must normalize that to `SenderClosed` too, not
        // surface a raw `Io(ConnectionReset)`.
        #[cfg(target_os = "linux")]
        #[test]
        fn peer_reset_with_unread_data_is_sender_closed() {
            use std::os::unix::net::UnixStream;
            let (a, b) = UnixStream::pair().unwrap();
            // Put unread data into b's receive queue (a -> b), then close b
            // without reading it: a's subsequent read gets ECONNRESET.
            (&a).write_all(b"unread junk").unwrap();
            drop(b);
            let mut recver: Receiver<u32> = Receiver::new(a);
            let error = recver.recv().unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::SenderClosed),
                "Unexpected error: {error:?}",
            );
        }

        #[test]
        fn completes_when_data_arrives_from_another_thread() {
            // Cross-thread wakeup: a blocking `recv` must return the value
            // another thread sends, whichever side reaches the socket first.
            // Which interleaving actually occurs is scheduler-dependent and
            // cannot be forced portably from userspace — a previous version
            // "arranged" for the receiver to block first with a 1s sleep,
            // which only made that interleaving likely, at the cost of a
            // timing dependency and a second of wall clock. Both orders are
            // correct and both occur across runs; the "empty channel waits
            // instead of erroring" property is pinned deterministically by
            // the `recv_timeout` tests, which drive the wait path on a channel
            // that provably never receives data.
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            let send_thread = thread::spawn(move || {
                sender.send(&42).unwrap();
            });
            assert_eq!(recver.recv().unwrap(), 42);
            send_thread.join().unwrap();
        }
    }

    mod recv_timeout {
        // Timing policy, so these stay deterministic without a mocked clock:
        // lower bounds on elapsed time are asserted tightly — the kernel
        // never wakes a poll before its deadline, so "returned too early" is
        // a real bug regardless of machine load. Upper bounds are asserted
        // only as hang detectors, at ceilings orders of magnitude above the
        // deadline, so a heavily loaded CI runner can't flake them. Nothing
        // in here sleeps to sequence events.

        use super::*;

        /// A raw socketpair for driving unframed bytes at a `Receiver`: `.0` is
        /// the write end (a plain `UnixStream`), `.1` is wrapped in the typed
        /// `Receiver` under test. Replaces the old raw-`interprocess`-pipe
        /// fixtures so the framing/poison tests run over the real socket
        /// transport.
        fn raw_channel<T: Serialize + DeserializeOwned>() -> (UnixStream, Receiver<T>) {
            let (writer, reader) = UnixStream::pair().unwrap();
            (writer, Receiver::new(reader))
        }

        #[test]
        fn primitive_u32() {
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            sender.send(&42).unwrap();
            assert_eq!(recver.recv_timeout(Duration::from_secs(1)).unwrap(), 42);
        }

        #[test]
        fn string() {
            let (mut sender, mut recver) = channel_pair::<String>().unwrap();
            sender.send(&"Hello, World!".to_string()).unwrap();
            assert_eq!(
                recver.recv_timeout(Duration::from_secs(1)).unwrap(),
                "Hello, World!"
            );
        }

        #[test]
        fn custom_struct() {
            #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
            struct MyStruct {
                a: u32,
                b: String,
            }

            let (mut sender, mut recver) = channel_pair::<MyStruct>().unwrap();
            sender
                .send(&MyStruct {
                    a: 42,
                    b: "Hello, World!".to_string(),
                })
                .unwrap();
            assert_eq!(
                recver.recv_timeout(Duration::from_secs(1)).unwrap(),
                MyStruct {
                    a: 42,
                    b: "Hello, World!".to_string()
                }
            );
        }

        #[test]
        fn dropped_sender() {
            let (sender, mut recver) = channel_pair::<u32>().unwrap();
            drop(sender);
            let error = recver.recv_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::SenderClosed),
                "Unexpected error: {:?}",
                error,
            );
        }

        #[test]
        fn completes_when_data_arrives_from_another_thread() {
            // Cross-thread wakeup for the timeout path — see the blocking
            // twin in `recv::completes_when_data_arrives_from_another_thread`
            // for why no sleep "arranges" the receiver to block first: the
            // interleaving can't be forced portably, both orders are correct,
            // and the genuinely-waiting case is pinned deterministically by
            // `timeout` below (a channel that provably never receives data).
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            let send_thread = thread::spawn(move || {
                sender.send(&42).unwrap();
            });
            assert_eq!(recver.recv_timeout(Duration::from_secs(10)).unwrap(), 42);
            send_thread.join().unwrap();
        }

        #[test]
        fn timeout() {
            let (_sender, mut recver) = channel_pair::<u32>().unwrap();
            let response = recver.recv_timeout(Duration::from_secs(1));
            let error = response.unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::Timeout),
                "Unexpected error: {:?}",
                error,
            );
        }

        #[test]
        fn zero_timeout_with_data_ready() {
            // Data already in channel, zero timeout should still succeed
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            sender.send(&42).unwrap();
            assert_eq!(recver.recv_timeout(Duration::ZERO).unwrap(), 42);
        }

        #[test]
        fn zero_timeout_without_data() {
            // No data, zero timeout should fail immediately
            let (_sender, mut recver) = channel_pair::<u32>().unwrap();
            let error = recver.recv_timeout(Duration::ZERO).unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::Timeout),
                "Unexpected error: {:?}",
                error,
            );
        }

        #[test]
        fn very_short_timeout_without_data() {
            // Very short timeout (1ms) without data
            let (_sender, mut recver) = channel_pair::<u32>().unwrap();
            let start = Instant::now();
            let error = recver.recv_timeout(Duration::from_millis(1)).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                matches!(error, ChannelRecvError::Timeout),
                "Unexpected error: {:?}",
                error,
            );
            // Hang detector only (see the mod-level timing policy): far above
            // the 1ms deadline so scheduler delay can't flake it, far below
            // the 65s a poll stuck on its full u16::MAX-ms window would take.
            assert!(elapsed < Duration::from_secs(10));
        }

        #[test]
        fn large_message() {
            // Large message that may require multiple read chunks
            // Note: socket buffers are finite, so we send/recv concurrently
            let (mut sender, mut recver) = channel_pair::<Vec<u8>>().unwrap();
            let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
            let expected = large_data.clone();

            // Send in a separate thread to avoid blocking on full socket buffer
            let send_thread = thread::spawn(move || {
                sender.send(&large_data).unwrap();
            });

            let received = recver.recv_timeout(Duration::from_secs(5)).unwrap();
            send_thread.join().unwrap();
            assert_eq!(received, expected);
        }

        #[test]
        fn multiple_sequential_messages() {
            // Multiple messages in sequence
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            for i in 0..10 {
                sender.send(&i).unwrap();
            }
            for i in 0..10 {
                assert_eq!(recver.recv_timeout(Duration::from_secs(1)).unwrap(), i);
            }
        }

        #[test]
        fn timeout_waiting_for_length_bytes() {
            // Sender sends nothing, timeout waiting for length prefix
            // This is essentially the same as the `timeout` test but with explicit timing check
            let (_sender, mut recver) = channel_pair::<u32>().unwrap();
            let start = Instant::now();
            let error = recver.recv_timeout(Duration::from_millis(50)).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                matches!(error, ChannelRecvError::Timeout),
                "Unexpected error: {:?}",
                error,
            );
            // Verify timeout was respected (within reasonable margin)
            // Use >= 40ms to account for timing jitter
            assert!(
                elapsed >= Duration::from_millis(40),
                "Timeout returned too quickly: {:?}",
                elapsed
            );
            // Hang detector only (see the mod-level timing policy): far above
            // the 50ms deadline so scheduler delay can't flake it, far below
            // the 65s a poll stuck on its full u16::MAX-ms window would take.
            assert!(
                elapsed < Duration::from_secs(10),
                "Timeout took too long: {:?}",
                elapsed
            );
        }

        #[test]
        fn timeout_waiting_for_payload() {
            // Sender sends length but not payload - tests timeout during payload read
            let (mut raw_sender, mut recver) = raw_channel::<u32>();

            // Send only the length prefix (4 bytes), not the payload
            let fake_len: u32 = 100;
            raw_sender.write_all(&fake_len.to_le_bytes()).unwrap();

            // Keep sender alive to prevent EOF
            let _keep_sender = raw_sender;

            let start = Instant::now();
            let error = recver.recv_timeout(Duration::from_millis(50)).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                matches!(error, ChannelRecvError::Timeout),
                "Unexpected error: {:?}",
                error,
            );
            // Use >= 40ms to account for timing jitter
            assert!(
                elapsed >= Duration::from_millis(40),
                "Timeout returned too quickly: {:?}",
                elapsed
            );
        }

        #[test]
        fn sender_closes_after_partial_length() {
            // Sender sends partial length then closes
            let (mut raw_sender, mut recver) = raw_channel::<u32>();

            // Send only 2 of 4 length bytes, then close
            raw_sender.write_all(&[1, 2]).unwrap();
            drop(raw_sender);

            let error = recver.recv_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::SenderClosed),
                "Unexpected error: {:?}",
                error,
            );
        }

        #[test]
        fn sender_closes_after_partial_payload() {
            // Sender sends length + partial payload then closes
            let (mut raw_sender, mut recver) = raw_channel::<Vec<u8>>();

            // Send length indicating 100 bytes, but only send 10
            let len: u32 = 100;
            raw_sender.write_all(&len.to_le_bytes()).unwrap();
            raw_sender.write_all(&[0u8; 10]).unwrap();
            drop(raw_sender);

            let error = recver.recv_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(error, ChannelRecvError::SenderClosed),
                "Unexpected error: {:?}",
                error,
            );
        }
    }

    mod raw {
        use super::*;

        #[test]
        fn roundtrip_short_payload() {
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            sender.send_raw(b"hello").unwrap();
            assert_eq!(
                recver.recv_raw_timeout(Duration::from_secs(1)).unwrap(),
                b"hello"
            );
        }

        #[test]
        fn roundtrip_empty_payload() {
            // Zero-length payload still goes over the wire as
            // [4-byte length=0] [0 bytes payload]. Receiver must complete.
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            sender.send_raw(b"").unwrap();
            assert_eq!(
                recver.recv_raw_timeout(Duration::from_secs(1)).unwrap(),
                b""
            );
        }

        #[test]
        fn roundtrip_near_max_payload() {
            // A payload just under MAX_MESSAGE_SIZE must round-trip cleanly.
            // Send/recv concurrently so we don't deadlock against the socket's
            // OS-level buffer.
            let payload: Vec<u8> = (0..MAX_MESSAGE_SIZE - 4).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            let send_thread = thread::spawn(move || {
                sender.send_raw(&payload).unwrap();
            });
            let received = recver.recv_raw_timeout(Duration::from_secs(10)).unwrap();
            send_thread.join().unwrap();
            assert_eq!(received, expected);
        }

        #[test]
        fn payload_over_max_size_rejected_on_send() {
            // We can't actually allocate the over-sized buffer cheaply, but
            // we can verify that `send_raw` enforces the same limit as
            // `send`: it bails before touching the underlying fd, so a
            // dummy peer-less sender suffices.
            let (sender, _recver) = UnixStream::pair().unwrap();
            let mut sender: Sender<u32> = Sender::new(sender);
            let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
            let err = sender.send_raw(&oversized).unwrap_err();
            assert!(
                matches!(
                    err,
                    ChannelSendError::MessageTooLarge {
                        size,
                        max: MAX_MESSAGE_SIZE,
                    } if size == MAX_MESSAGE_SIZE + 1
                ),
                "Unexpected error: {err:?}",
            );
        }

        #[test]
        fn dropped_sender_gives_eof_to_recv_raw_timeout() {
            let (sender, mut recver) = channel_pair::<u32>().unwrap();
            drop(sender);
            // EOF should be detected and surfaced as an error well before
            // the timeout fires.
            assert!(recver.recv_raw_timeout(Duration::from_secs(1)).is_err());
        }

        #[test]
        fn length_prefix_is_four_bytes_little_endian() {
            // Pin the wire format: a `send_raw` of N bytes writes exactly
            // 4+N bytes total, with the leading 4 bytes being the
            // little-endian u32 length. The fork+exec daemon child relies on
            // this format being stable across build_id mismatches (otherwise
            // the handshake check itself can't be validated).
            let (sender, mut raw_recver) = UnixStream::pair().unwrap();
            let mut typed_sender: Sender<u32> = Sender::new(sender);
            typed_sender.send_raw(b"abc").unwrap();
            drop(typed_sender);
            let mut on_wire = Vec::new();
            raw_recver.read_to_end(&mut on_wire).unwrap();
            assert_eq!(on_wire, b"\x03\x00\x00\x00abc");
        }

        #[test]
        fn send_typed_then_recv_raw_observes_postcard_bytes() {
            // Encoding asymmetry: `send` postcard-encodes; `recv_raw_timeout`
            // returns the raw bytes that were sent. The receiver of a
            // build-id handshake therefore sees exactly what the sender
            // wrote, not postcard-decoded. Pin this with a value that
            // postcard would encode non-trivially.
            #[derive(Debug, Serialize, Deserialize)]
            struct Msg {
                a: u32,
                b: String,
            }
            let (mut sender, mut recver) = channel_pair::<Msg>().unwrap();
            sender
                .send(&Msg {
                    a: 0x42,
                    b: "hi".into(),
                })
                .unwrap();
            let raw = recver.recv_raw_timeout(Duration::from_secs(1)).unwrap();
            // postcard varint-encodes integers and length-prefixes the
            // string. We don't depend on the exact bytes here, just that
            // we got something non-empty back.
            assert!(!raw.is_empty());
        }
    }

    /// Poisoning: a receive that consumes part of a frame and then fails must
    /// desynchronize the endpoint so the misframing surfaces as a loud
    /// `Desynchronized` error rather than silent corruption — while a clean idle
    /// timeout stays retryable.
    mod poison {
        use super::*;

        /// Same raw-socketpair fixture as `recv_timeout::raw_channel`.
        fn raw_channel<T: Serialize + DeserializeOwned>() -> (UnixStream, Receiver<T>) {
            let (writer, reader) = UnixStream::pair().unwrap();
            (writer, Receiver::new(reader))
        }

        #[test]
        fn mid_frame_recv_timeout_poisons_receiver() {
            let (mut raw_sender, mut recver) = raw_channel::<u32>();
            // Length prefix promises 100 payload bytes; send none of them.
            raw_sender.write_all(&100u32.to_le_bytes()).unwrap();
            let _keep_sender = raw_sender; // hold open so this is a timeout, not EOF

            let err = recver
                .recv_raw_timeout(Duration::from_millis(50))
                .unwrap_err();
            assert!(matches!(err, ChannelRecvError::Timeout), "got {err:?}");
            // The prefix is consumed; the receiver is now desynchronized and
            // every later receive fails fast without touching the socket.
            let err = recver.recv_raw_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(err, ChannelRecvError::Desynchronized),
                "got {err:?}"
            );
            // Poison is visible on the blocking path too.
            let err = recver.recv().unwrap_err();
            assert!(
                matches!(err, ChannelRecvError::Desynchronized),
                "got {err:?}"
            );
        }

        #[test]
        fn clean_idle_recv_timeout_does_not_poison() {
            let (mut sender, mut recver) = channel_pair::<u32>().unwrap();
            // Nothing sent yet: this timeout consumes 0 bytes and must not
            // poison, so idle poll loops keep working.
            let err = recver
                .recv_raw_timeout(Duration::from_millis(50))
                .unwrap_err();
            assert!(matches!(err, ChannelRecvError::Timeout), "got {err:?}");
            sender.send_raw(b"ok").unwrap();
            assert_eq!(
                recver.recv_raw_timeout(Duration::from_secs(1)).unwrap(),
                b"ok"
            );
        }

        #[test]
        fn message_too_large_poisons_receiver() {
            let (mut raw_sender, mut recver) = raw_channel::<u32>();
            // Prefix consumed, oversized payload left unread → desynced.
            let too_big = (MAX_MESSAGE_SIZE as u32) + 1;
            raw_sender.write_all(&too_big.to_le_bytes()).unwrap();
            let _keep_sender = raw_sender;

            let err = recver.recv_raw_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(err, ChannelRecvError::MessageTooLarge { .. }),
                "got {err:?}"
            );
            let err = recver.recv_raw_timeout(Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(err, ChannelRecvError::Desynchronized),
                "got {err:?}"
            );
        }
    }
}
