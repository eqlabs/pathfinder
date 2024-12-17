use std::future::Future;

use tokio::sync::mpsc::{self, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

/// Use the sender to yield items to the stream.
///
/// ### Warning
///
/// Implementor of the future must ensure that the `src` future __exits if the
/// sender fails to send an item__ (ie. fails to yield an item to the stream).
/// Otherwise, the `src` future will never complete and will keep running,
/// because it is detached via `tokio::spawn`.
pub fn from_future<T, U, V>(src: U) -> impl Stream<Item = T>
where
    U: FnOnce(Sender<T>) -> V + Send + 'static,
    V: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(src(tx));

    ReceiverStream::new(rx)
}

/// Use the sender to yield items to the stream.
///
/// ### Warning
///
/// Implementor of the closure must ensure that the `src` closure __exits if the
/// sender fails to send an item__ (ie. fails to yield an item to the stream).
/// Otherwise, the `src` closure will never complete and will keep running,
/// because it is detached via `std::thread::spawn`.
pub fn from_blocking<T, U>(src: U) -> impl Stream<Item = T>
where
    T: Send + 'static,
    U: FnOnce(Sender<T>) + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || src(tx));

    ReceiverStream::new(rx)
}
