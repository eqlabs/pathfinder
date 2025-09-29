//! Rate limiting transport wrapper for libp2p connections.
//!
//! This module provides a transport wrapper that applies rate limiting to
//! both incoming and outgoing data on libp2p connections.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::num::NonZeroU32;
//! use crate::rate_limit::RateLimit;
//!
//! // Wrap an existing transport with rate limiting
//! let rate_limited_transport = RateLimit::new(
//!     base_transport,
//!     NonZeroU32::new(1024).unwrap(), // 1KB/s read limit
//!     NonZeroU32::new(2048).unwrap(), // 2KB/s write limit
//! );
//! ```

use std::future::Future;
use std::io;
use std::num::NonZeroU32;
use std::pin::{pin, Pin};
use std::task::{self, Poll};

use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};

/// Minimum value to be used as read/write byte per second limit that should
/// provide normal P2P network behaviour and avoid timeouts.
pub const MIN_BYTES_PER_SEC: NonZeroU32 = NonZeroU32::new(10 * 1024 * 1024).unwrap();

/// A string representation of [MIN_BYTES_PER_SEC] for use in config
/// messages.
pub const MIN_BYTES_PER_SEC_PRETTY: &str = "10 * 1024 * 1024";

/// A rate-limiting wrapper for libp2p transports.
///
/// This struct wraps an existing transport and applies rate limiting to all
/// connections created through it. It maintains separate read and write
/// quotas for control over bandwidth usage.
pub struct RateLimit<T> {
    inner: T,
    read_quota: governor::Quota,
    write_quota: governor::Quota,
}

impl<T: libp2p::core::Transport> RateLimit<T> {
    pub fn new(
        inner: T,
        max_read_bytes_per_sec: NonZeroU32,
        max_write_bytes_per_sec: NonZeroU32,
    ) -> Self {
        let read_quota = governor::Quota::per_second(max_read_bytes_per_sec);
        let write_quota = governor::Quota::per_second(max_write_bytes_per_sec);
        Self {
            inner,
            read_quota,
            write_quota,
        }
    }
}

impl<T> libp2p::core::Transport for RateLimit<T>
where
    T: libp2p::core::Transport + Unpin,
    T::Output: futures::AsyncRead + futures::AsyncWrite,
    T::Error: 'static,
    T::ListenerUpgrade: Unpin,
    T::Dial: Unpin,
{
    type Output = Connection<T::Output>;
    type Error = T::Error;
    type ListenerUpgrade = ListenerUpgrade<T>;
    type Dial = DialFuture<T::Dial, T>;

    fn listen_on(
        &mut self,
        id: libp2p::core::transport::ListenerId,
        addr: libp2p::Multiaddr,
    ) -> Result<(), libp2p::TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: libp2p::core::transport::ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: libp2p::Multiaddr,
        opts: libp2p::core::transport::DialOpts,
    ) -> Result<Self::Dial, libp2p::TransportError<Self::Error>> {
        let inner_dial = self.inner.dial(addr, opts)?;

        Ok(DialFuture {
            read_quota: self.read_quota,
            write_quota: self.write_quota,
            f: inner_dial,
            _marker: std::marker::PhantomData,
        })
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<libp2p::core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();

        let inner = Pin::new(&mut this.inner);
        let inner = task::ready!(inner.poll(cx));

        let upgrade = inner.map_upgrade(|upgrade| {
            ListenerUpgrade(RateLimit {
                inner: upgrade,
                read_quota: this.read_quota,
                write_quota: this.write_quota,
            })
        });

        Poll::Ready(upgrade)
    }
}

/// A rate-limited connection that enforces bandwidth limits on read/write
/// operations.
///
/// Rate limiting is applied before actual I/O operations, so if the rate
/// limit is exceeded, the operation will wait until sufficient permits
/// are available.
pub struct Connection<T: futures::AsyncRead + futures::AsyncWrite> {
    reader: Limited<futures::io::ReadHalf<T>>,
    writer: Limited<futures::io::WriteHalf<T>>,
}

impl<T: futures::AsyncRead + futures::AsyncWrite> Connection<T> {
    pub fn new(inner: T, read_quota: governor::Quota, write_quota: governor::Quota) -> Self {
        let (r, w) = inner.split();
        Connection {
            reader: Limited::new(r, read_quota),
            writer: Limited::new(w, write_quota),
        }
    }
}

impl<T: futures::AsyncRead + futures::AsyncWrite> futures::AsyncRead for Connection<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let to_read = std::cmp::min(buf.len(), self.reader.limiter.max_capacity());
        let n = to_read
            .try_into()
            .map(|n| NonZeroU32::new(n).unwrap())
            .expect("conversion error");

        let until_fut = self.reader.limiter.until_n_ready(n);
        let until_poll = pin!(until_fut).poll(cx);
        task::ready!(until_poll).expect("n capped to max capacity");

        self.reader
            .resource
            .read(&mut buf[..to_read])
            .poll_unpin(cx)
    }
}

impl<T: futures::AsyncRead + futures::AsyncWrite> futures::AsyncWrite for Connection<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let to_write = std::cmp::min(buf.len(), self.writer.limiter.max_capacity());
        let n = to_write
            .try_into()
            .map(|n| NonZeroU32::new(n).unwrap())
            .expect("conversion error");

        let until_fut = self.writer.limiter.until_n_ready(n);
        let until_poll = pin!(until_fut).poll(cx);
        task::ready!(until_poll).expect("n capped to max capacity");

        self.writer.resource.write(&buf[..to_write]).poll_unpin(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.writer.resource.flush().poll_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.writer.resource.close().poll_unpin(cx)
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ListenerUpgrade<T: libp2p::core::Transport>(RateLimit<T::ListenerUpgrade>);

impl<T> Future for ListenerUpgrade<T>
where
    T: libp2p::core::Transport,
    T::Output: futures::AsyncRead + futures::AsyncWrite,
    T::ListenerUpgrade: Unpin,
{
    type Output = Result<Connection<T::Output>, T::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let inner_poll = self.0.inner.poll_unpin(cx);
        let inner = task::ready!(inner_poll)?;
        let conn = Connection::new(inner, self.0.read_quota, self.0.write_quota);
        Poll::Ready(Ok(conn))
    }
}

struct Limited<T> {
    resource: T,
    limiter: Limiter,
}

impl<T> Limited<T> {
    fn new(resource: T, quota: governor::Quota) -> Self {
        let limiter = Limiter {
            inner: governor::DefaultDirectRateLimiter::direct(quota),
            max_capacity: quota.burst_size(),
        };

        Self { resource, limiter }
    }
}

struct Limiter {
    inner: governor::DefaultDirectRateLimiter,
    max_capacity: NonZeroU32,
}

impl Limiter {
    /// Waits until `n` permits are available and consumes them.
    ///
    /// Returns `InsufficientCapacity` if `n` exceeds the maximum capacity
    /// of the limiter.
    async fn until_n_ready(&self, n: NonZeroU32) -> Result<(), governor::InsufficientCapacity> {
        self.inner.until_n_ready(n).await
    }

    /// Returns the maximum burst size of this limiter. Attempting to wait
    /// for more than this amount will result in an
    /// `InsufficientCapacity` error.
    fn max_capacity(&self) -> usize {
        self.max_capacity
            .get()
            .try_into()
            .expect("conversion error")
    }
}

/// A concrete future to avoid boxing.
#[must_use = "futures do nothing unless polled"]
pub struct DialFuture<F, T> {
    read_quota: governor::Quota,
    write_quota: governor::Quota,
    f: F,
    _marker: std::marker::PhantomData<T>,
}

impl<F, T> Future for DialFuture<F, T>
where
    F: Future<Output = Result<T::Output, T::Error>> + Unpin,
    T: libp2p::core::Transport + Unpin,
    T::Output: futures::AsyncRead + futures::AsyncWrite,
{
    type Output = Result<Connection<T::Output>, T::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let f = Pin::new(&mut this.f);
        let inner = task::ready!(f.poll(cx))?;

        let conn = Connection::new(inner, this.read_quota, this.write_quota);

        Poll::Ready(Ok(conn))
    }
}
