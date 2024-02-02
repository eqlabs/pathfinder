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

    define_protocol!(Headers, "/starknet/headers/1");
    define_protocol!(StateDiffs, "/starknet/state_diffs/1");
    define_protocol!(Classes, "/starknet/classes/1");
    define_protocol!(Transactions, "/starknet/transactions/1");
    define_protocol!(Receipts, "/starknet/receipts/1");
    define_protocol!(Events, "/starknet/events/1");

    pub const PROTOCOLS: &[&str] = &[
        Headers::NAME,
        StateDiffs::NAME,
        Classes::NAME,
        Transactions::NAME,
        Receipts::NAME,
        Events::NAME,
    ];
}

pub(crate) mod codec {
    use super::protocol;
    use async_trait::async_trait;
    use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use p2p_proto::consts::MESSAGE_SIZE_LIMIT;
    use p2p_proto::{class, event, header, proto, receipt, state, transaction};
    use p2p_proto::{ToProtobuf, TryFromProtobuf};
    use p2p_stream::Codec;
    use std::marker::PhantomData;

    pub type Headers = SyncCodec<
        protocol::Headers,
        header::BlockHeadersRequest,
        header::BlockHeadersResponse,
        proto::header::BlockHeadersRequest,
        proto::header::BlockHeadersResponse,
    >;

    pub type StateDiffs = SyncCodec<
        protocol::StateDiffs,
        state::StateDiffsRequest,
        state::StateDiffsResponse,
        proto::state::StateDiffsRequest,
        proto::state::StateDiffsResponse,
    >;

    pub type Classes = SyncCodec<
        protocol::Classes,
        class::ClassesRequest,
        class::ClassesResponse,
        proto::class::ClassesRequest,
        proto::class::ClassesResponse,
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

            io.take(MESSAGE_SIZE_LIMIT as u64)
                .read_to_end(&mut buf)
                .await?;

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

            if encoded_len > MESSAGE_SIZE_LIMIT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Encoded length {} exceeds the maximum buffer size {}",
                        encoded_len, MESSAGE_SIZE_LIMIT
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
}
