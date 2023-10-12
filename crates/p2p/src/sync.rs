pub mod protocol {
    use libp2p::core::upgrade::ProtocolName;

    macro_rules! define_protocol {
        ($type_name:ident, $name:literal) => {
            #[derive(Debug, Clone, Default)]
            pub struct $type_name;

            impl $type_name {
                const NAME: &[u8] = $name;
            }

            impl ProtocolName for $type_name {
                fn protocol_name(&self) -> &[u8] {
                    Self::NAME
                }
            }
        };
    }

    define_protocol!(Headers, b"/core/headers-sync/1");
    define_protocol!(Bodies, b"/core/bodies-sync/1");
    define_protocol!(Transactions, b"/core/transactions-sync/1");
    define_protocol!(Receipts, b"/core/receipts-sync/1");
    define_protocol!(Events, b"/core/events-sync/1");
}

pub mod codec {
    use super::protocol;
    use async_trait::async_trait;
    use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use libp2p::core::upgrade::ProtocolName;
    use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed};
    use libp2p::request_response::Codec;
    use p2p_proto_v1::consts::MESSAGE_SIZE_LIMIT;
    use p2p_proto_v1::{block, event, proto, receipt, transaction};
    use p2p_proto_v1::{ToProtobuf, TryFromProtobuf};
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
        block::BlockBodiesResponse,
        proto::block::BlockBodiesRequest,
        proto::block::BlockBodiesResponse,
    >;

    pub type Transactions = SyncCodec<
        protocol::Transactions,
        transaction::TransactionsRequest,
        transaction::TransactionsResponse,
        proto::transaction::TransactionsRequest,
        proto::transaction::TransactionsResponse,
    >;

    pub type Receipts = SyncCodec<
        protocol::Receipts,
        receipt::ReceiptsRequest,
        receipt::ReceiptsResponse,
        proto::receipt::ReceiptsRequest,
        proto::receipt::ReceiptsResponse,
    >;

    pub type Events = SyncCodec<
        protocol::Events,
        event::EventsRequest,
        event::EventsResponse,
        proto::event::EventsRequest,
        proto::event::EventsResponse,
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
        Protocol: ProtocolName + Send + Clone,
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
        let dto = Dto::try_from_protobuf(prost_dto, "TODO")?;
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
