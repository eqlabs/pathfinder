//! request/streaming-response protocol and codec definitions for sync

pub mod protocol {
    macro_rules! define_protocol {
        ($type_name:ident, $name:literal) => {
            #[derive(Debug, Clone, Default)]
            pub struct $type_name;

            impl $type_name {
                pub const NAME: &'static str = $name;
            }

            impl AsRef<str> for $type_name {
                fn as_ref(&self) -> &str {
                    Self::NAME
                }
            }
        };
    }

    define_protocol!(Headers, "/starknet/headers/0.1.0-rc.0");
    define_protocol!(StateDiffs, "/starknet/state_diffs/0.1.0-rc.0");
    define_protocol!(Classes, "/starknet/classes/0.1.0-rc.0");
    define_protocol!(Transactions, "/starknet/transactions/0.1.0-rc.0");
    define_protocol!(Events, "/starknet/events/0.1.0-rc.0");

    pub const PROTOCOLS: &[&str] = &[
        Headers::NAME,
        StateDiffs::NAME,
        Classes::NAME,
        Transactions::NAME,
        Events::NAME,
    ];
}

pub(crate) mod codec {
    use std::marker::PhantomData;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use futures::future::BoxFuture;
    use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use p2p_proto::{class, event, header, proto, state, transaction, ToProtobuf, TryFromProtobuf};
    use p2p_stream::Codec;

    use super::protocol;

    pub const ONE_MIB: usize = 1024 * 1024;
    pub const FOUR_MIB: usize = 4 * ONE_MIB;

    pub type Headers = SyncCodec<
        protocol::Headers,
        header::BlockHeadersRequest,
        header::BlockHeadersResponse,
        proto::header::BlockHeadersRequest,
        proto::header::BlockHeadersResponse,
        ONE_MIB,
    >;

    pub type StateDiffs = SyncCodec<
        protocol::StateDiffs,
        state::StateDiffsRequest,
        state::StateDiffsResponse,
        proto::state::StateDiffsRequest,
        proto::state::StateDiffsResponse,
        ONE_MIB,
    >;

    pub type Classes = SyncCodec<
        protocol::Classes,
        class::ClassesRequest,
        class::ClassesResponse,
        proto::class::ClassesRequest,
        proto::class::ClassesResponse,
        FOUR_MIB,
    >;

    pub type Transactions = SyncCodec<
        protocol::Transactions,
        transaction::TransactionsRequest,
        transaction::TransactionsResponse,
        proto::transaction::TransactionsRequest,
        proto::transaction::TransactionsResponse,
        ONE_MIB,
    >;

    pub type Events = SyncCodec<
        protocol::Events,
        event::EventsRequest,
        event::EventsResponse,
        proto::event::EventsRequest,
        proto::event::EventsResponse,
        ONE_MIB,
    >;

    #[derive(Clone)]
    pub struct ProdCodec<Protocol, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize>(
        PhantomData<(Protocol, Req, Resp, ProstReq, ProstResp)>,
    );

    impl<A, B, C, D, E, const F: usize> Default for ProdCodec<A, B, C, D, E, F> {
        fn default() -> Self {
            Self(Default::default())
        }
    }

    /// An enum to prevent _generic parameter explosion_ in the outer
    /// behaviour.
    ///
    /// [`SyncCodec::ForTest`] falls back to [`SyncCodec::Prod`] unless the
    /// caller explicitly sets a read/write factory.
    #[derive(Clone)]
    pub enum SyncCodec<Protocol, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize> {
        Prod(ProdCodec<Protocol, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>),
        #[cfg(test)]
        ForTest(TestCodec<Protocol, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>),
    }

    impl<A, B, C, D, E, const F: usize> Default for SyncCodec<A, B, C, D, E, F> {
        fn default() -> Self {
            Self::Prod(Default::default())
        }
    }

    #[cfg(test)]
    impl<A, B, C, D, E, const F: usize> SyncCodec<A, B, C, D, E, F> {
        pub fn for_test() -> Self {
            Self::ForTest(Default::default())
        }
    }

    #[async_trait]
    impl<Protocol, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize> Codec
        for ProdCodec<Protocol, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>
    where
        Protocol: AsRef<str> + Send + Clone,
        Req: TryFromProtobuf<ProstReq> + ToProtobuf<ProstReq> + Send,
        Resp: TryFromProtobuf<ProstResp> + ToProtobuf<ProstResp> + Send,
        ProstReq: prost::Message + Default,
        ProstResp: prost::Message + Default,
    {
        type Protocol = Protocol;
        type Request = Req;
        type Response = Resp;

        async fn read_request<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
        ) -> std::io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
        {
            let mut buf = Vec::new();

            io.take(ONE_MIB as u64).read_to_end(&mut buf).await?;

            let prost_dto = ProstReq::decode(buf.as_ref())?;
            let dto = Req::try_from_protobuf(prost_dto, std::any::type_name::<ProstReq>())?;

            Ok(dto)
        }

        async fn read_response<T>(
            &mut self,
            _: &Self::Protocol,
            mut io: &mut T,
        ) -> std::io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
        {
            let encoded_len: usize = unsigned_varint::aio::read_usize(&mut io)
                .await
                .map_err(Into::<std::io::Error>::into)?;

            if encoded_len > RESPONSE_SIZE_LIMIT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Encoded length {} exceeds the maximum buffer size {}",
                        encoded_len, RESPONSE_SIZE_LIMIT
                    ),
                ));
            }

            let mut buf = vec![0u8; encoded_len];
            io.read_exact(&mut buf).await?;

            let prost_dto = ProstResp::decode(buf.as_ref())?;
            let dto = Resp::try_from_protobuf(prost_dto, std::any::type_name::<ProstResp>())?;

            Ok(dto)
        }

        async fn write_request<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            request: Self::Request,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            let data = request.to_protobuf().encode_to_vec();
            io.write_all(&data).await?;
            Ok(())
        }

        async fn write_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            response: Self::Response,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            let data = response.to_protobuf().encode_length_delimited_to_vec();
            io.write_all(&data).await?;
            Ok(())
        }
    }

    #[async_trait]
    impl<Protocol, Req, Resp, ProstReq, ProstResp, const RESPONSE_SIZE_LIMIT: usize> Codec
        for SyncCodec<Protocol, Req, Resp, ProstReq, ProstResp, RESPONSE_SIZE_LIMIT>
    where
        Protocol: AsRef<str> + Send + Sync + Clone,
        Req: TryFromProtobuf<ProstReq> + ToProtobuf<ProstReq> + Send,
        Resp: TryFromProtobuf<ProstResp> + ToProtobuf<ProstResp> + Send,
        ProstReq: prost::Message + Default,
        ProstResp: prost::Message + Default,
    {
        type Protocol = Protocol;
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
            match self {
                Self::Prod(codec) => codec.read_request(protocol, io).await,
                #[cfg(test)]
                Self::ForTest(codec) => codec.read_request(protocol, io).await,
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
            match self {
                Self::Prod(codec) => codec.read_response(protocol, io).await,
                #[cfg(test)]
                Self::ForTest(codec) => codec.read_response(protocol, io).await,
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
            match self {
                Self::Prod(codec) => codec.write_request(protocol, io, request).await,
                #[cfg(test)]
                Self::ForTest(codec) => codec.write_request(protocol, io, request).await,
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
            match self {
                Self::Prod(codec) => codec.write_response(protocol, io, response).await,
                #[cfg(test)]
                Self::ForTest(codec) => codec.write_response(protocol, io, response).await,
            }
        }
    }

    pub type TypeErasedReadFun<T> = Box<
        dyn FnMut(&mut TypeErasedAsyncRead<'_>) -> BoxFuture<'static, std::io::Result<T>> + Send,
    >;
    pub type TypeErasedWriteFun<T> = Box<
        dyn FnMut(&mut TypeErasedAsyncWrite<'_>, T) -> BoxFuture<'static, std::io::Result<()>>
            + Send,
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

    /// Falls back to [`SyncCodec::Prod`] unless the caller expliticly sets a
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

    #[async_trait]
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
}
