use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use futures::{AsyncRead, AsyncWrite};
use p2p_proto::{ToProtobuf, TryFromProtobuf};
use p2p_stream::Codec;

use crate::sync::protocol::codec::{ProdCodec, SyncCodec};

pub type TypeErasedReadFun<T> =
    Box<dyn FnMut(&mut TypeErasedAsyncRead<'_>) -> BoxFuture<'static, std::io::Result<T>> + Send>;
pub type TypeErasedWriteFun<T> = Box<
    dyn FnMut(&mut TypeErasedAsyncWrite<'_>, T) -> BoxFuture<'static, std::io::Result<()>> + Send,
>;
pub type TypeErasedReadFactory<T> = Box<dyn Fn() -> TypeErasedReadFun<T> + Send>;
pub type TypeErasedWriteFactory<T> = Box<dyn Fn() -> TypeErasedWriteFun<T> + Send>;

#[allow(unused)]
pub struct TypeErasedAsyncRead<'a>(Box<dyn AsyncRead + Unpin + Send + 'a>);
#[allow(unused)]
pub struct TypeErasedAsyncWrite<'a>(Box<dyn AsyncWrite + Unpin + Send + 'a>);

impl<'a, A> From<A> for TypeErasedAsyncRead<'a>
where
    A: AsyncRead + Unpin + Send + 'a,
{
    fn from(x: A) -> Self {
        Self(Box::new(x))
    }
}

impl<'a, A> From<A> for TypeErasedAsyncWrite<'a>
where
    A: AsyncWrite + Unpin + Send + 'a,
{
    fn from(x: A) -> Self {
        Self(Box::new(x))
    }
}

/// Falls back to [`SyncCodec::Prod`] unless the caller explicitly sets a
/// read/write factory.
#[derive(Clone)]
pub struct TestCodec<Protocol, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize> {
    read_request_factory: Option<Arc<Mutex<TypeErasedReadFactory<Req>>>>,
    read_response_factory: Option<Arc<Mutex<TypeErasedReadFactory<Resp>>>>,
    write_request_factory: Option<Arc<Mutex<TypeErasedWriteFactory<Req>>>>,
    write_response_factory: Option<Arc<Mutex<TypeErasedWriteFactory<Resp>>>>,
    _x: PhantomData<(Protocol, ProstReq, ProstResp)>,
}

impl<A, B, C, D, E, const F: usize> Default for TestCodec<A, B, C, D, E, F> {
    fn default() -> Self {
        Self {
            read_request_factory: None,
            read_response_factory: None,
            write_request_factory: None,
            write_response_factory: None,
            _x: Default::default(),
        }
    }
}

#[cfg(test)]
#[allow(unused)]
impl<P, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize>
    SyncCodec<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>
{
    pub fn set_read_request_factory(mut self, factory: TypeErasedReadFactory<Req>) -> Self {
        if let Self::ForTest(codec) = &mut self {
            codec.read_request_factory = Some(Arc::new(Mutex::new(factory)));
        }
        self
    }

    pub fn set_read_response_factory(mut self, factory: TypeErasedReadFactory<Resp>) -> Self {
        if let Self::ForTest(codec) = &mut self {
            codec.read_response_factory = Some(Arc::new(Mutex::new(factory)));
        }
        self
    }

    pub fn set_write_request_factory(mut self, factory: TypeErasedWriteFactory<Req>) -> Self {
        if let Self::ForTest(codec) = &mut self {
            codec.write_request_factory = Some(Arc::new(Mutex::new(factory)));
        }
        self
    }

    pub fn set_write_response_factory(mut self, factory: TypeErasedWriteFactory<Resp>) -> Self {
        if let Self::ForTest(codec) = &mut self {
            codec.write_response_factory = Some(Arc::new(Mutex::new(factory)));
        }
        self
    }
}

impl<P, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize> Codec
    for TestCodec<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>
where
    P: AsRef<str> + Send + Sync + Clone,
    Req: TryFromProtobuf<ProstReq> + ToProtobuf<ProstReq> + Send,
    Resp: TryFromProtobuf<ProstResp> + ToProtobuf<ProstResp> + Send,
    ProstReq: prost::Message + Default,
    ProstResp: prost::Message + Default,
{
    type Protocol = P;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        match self.read_request_factory.as_ref() {
            Some(factory) => {
                let mut async_fn = factory.lock().unwrap()();
                async_fn(&mut io.into()).await
            }
            None => {
                ProdCodec::<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>::default()
                    .read_request(protocol, io)
                    .await
            }
        }
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        match self.read_response_factory.as_ref() {
            Some(factory) => {
                let mut async_fn = factory.lock().unwrap()();
                async_fn(&mut io.into()).await
            }
            None => {
                ProdCodec::<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>::default()
                    .read_response(protocol, io)
                    .await
            }
        }
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match self.write_request_factory.as_ref() {
            Some(factory) => {
                let mut async_fn = factory.lock().unwrap()();
                async_fn(&mut io.into(), request).await
            }
            None => {
                ProdCodec::<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>::default()
                    .write_request(protocol, io, request)
                    .await
            }
        }
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match self.write_response_factory.as_ref() {
            Some(factory) => {
                let mut async_fn = factory.lock().unwrap()();
                async_fn(&mut io.into(), response).await
            }
            None => {
                ProdCodec::<P, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>::default()
                    .write_response(protocol, io, response)
                    .await
            }
        }
    }
}
