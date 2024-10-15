use std::future::Future;

use tokio::sync::mpsc::{self, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

/// Use the sender to yield items to the stream.
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
pub fn from_blocking<T, U>(src: U) -> impl Stream<Item = T>
where
    T: Send + 'static,
    U: FnOnce(Sender<T>) + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || src(tx));

    ReceiverStream::new(rx)
}
