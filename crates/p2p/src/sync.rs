//! request-response protocol and codec definitions for sync
//!
//! FIXME: this is a temporary workaround until proper
//! streaming response protocol is implemented

pub mod protocol {
    macro_rules! define_protocol {
        ($type_name:ident, $name:literal) => {
            #[derive(Debug, Clone, Default)]
            pub struct $type_name;

            impl $type_name {
                pub const NAME: &str = $name;
            }

            impl AsRef<str> for $type_name {
                fn as_ref(&self) -> &str {
                    Self::NAME
                }
            }
        };
    }

    define_protocol!(Headers, "/core/headers-sync/1");
    define_protocol!(Bodies, "/core/bodies-sync/1");
    define_protocol!(Transactions, "/core/transactions-sync/1");
    define_protocol!(Receipts, "/core/receipts-sync/1");
    define_protocol!(Events, "/core/events-sync/1");

    pub const PROTOCOLS: &[&str] = &[
        Headers::NAME,
        Bodies::NAME,
        Transactions::NAME,
        Receipts::NAME,
        Events::NAME,
    ];
}

pub(crate) mod codec {
    use super::protocol;
    use async_trait::async_trait;
    use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed};
    use libp2p::request_response::Codec;
    use p2p_proto::consts::MESSAGE_SIZE_LIMIT;
    use p2p_proto::{block, event, proto, receipt, transaction};
    use p2p_proto::{ToProtobuf, TryFromProtobuf};
    use std::marker::PhantomData;

    pub type Headers = SyncCodec<
        protocol::Headers,
        block::BlockHeadersRequest,
        block::BlockHeadersResponse,
        proto::block::BlockHeadersRequest,
        proto::block::BlockHeadersResponse,
    >;

    pub type Bodies = SyncCodec<
        protocol::Bodies,
        block::BlockBodiesRequest,
        block::BlockBodiesResponseList,
        proto::block::BlockBodiesRequest,
        proto::block::BlockBodiesResponseList,
    >;

    pub type Transactions = SyncCodec<
        protocol::Transactions,
        transaction::TransactionsRequest,
        transaction::TransactionsResponseList,
        proto::transaction::TransactionsRequest,
        proto::transaction::TransactionsResponseList,
    >;

    pub type Receipts = SyncCodec<
        protocol::Receipts,
        receipt::ReceiptsRequest,
        receipt::ReceiptsResponseList,
        proto::receipt::ReceiptsRequest,
        proto::receipt::ReceiptsResponseList,
    >;

    pub type Events = SyncCodec<
        protocol::Events,
        event::EventsRequest,
        event::EventsResponseList,
        proto::event::EventsRequest,
        proto::event::EventsResponseList,
    >;

    #[derive(Clone, Debug)]
    pub struct SyncCodec<Protocol, Req, Resp, ProstReq, ProstResp>(
        PhantomData<(Protocol, Req, Resp, ProstReq, ProstResp)>,
    );

    impl<A, B, C, D, E> Default for SyncCodec<A, B, C, D, E> {
        fn default() -> Self {
            Self(Default::default())
        }
    }

    #[async_trait]
    impl<Protocol, Req, Resp, ProstReq, ProstResp> Codec
        for SyncCodec<Protocol, Req, Resp, ProstReq, ProstResp>
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
            decode(io, MESSAGE_SIZE_LIMIT).await
        }

        async fn read_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
        ) -> std::io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
        {
            decode(io, MESSAGE_SIZE_LIMIT).await
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
            encode(io, request).await
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
            encode(io, response).await
        }
    }

    async fn decode<Reader, ProstDto, Dto>(
        io: &mut Reader,
        max_buf_size: usize,
    ) -> std::io::Result<Dto>
    where
        Reader: AsyncRead + Unpin + Send,
        ProstDto: prost::Message + Default,
        Dto: TryFromProtobuf<ProstDto>,
    {
        let vec = read_length_prefixed(io, max_buf_size).await?;
        if vec.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let prost_dto = ProstDto::decode(vec.as_ref())?;
        let dto = Dto::try_from_protobuf(prost_dto, std::any::type_name::<ProstDto>())?;
        Ok(dto)
    }

    async fn encode<Writer, ProstDto, Dto>(io: &mut Writer, dto: Dto) -> std::io::Result<()>
    where
        Writer: AsyncWrite + Unpin + Send,
        ProstDto: prost::Message,
        Dto: ToProtobuf<ProstDto>,
    {
        let data = dto.to_protobuf().encode_to_vec();
        write_length_prefixed(io, &data).await?;
        io.close().await?;

        Ok(())
    }
}
