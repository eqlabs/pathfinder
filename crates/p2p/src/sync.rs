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
    use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use p2p_proto::consts::MESSAGE_SIZE_LIMIT;
    use p2p_proto::{block, event, proto, receipt, transaction};
    use p2p_proto::{ToProtobuf, TryFromProtobuf};
    use p2p_stream::Codec;
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
            decode::<T, ProstReq, Self::Request>(io, MESSAGE_SIZE_LIMIT)
                .await
                .and_then(|x| x.ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
        }

        async fn read_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
        ) -> std::io::Result<Option<Self::Response>>
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
        mut io: &mut Reader,
        max_buf_size: usize,
    ) -> std::io::Result<Option<Dto>>
    where
        Reader: AsyncRead + Unpin + Send,
        ProstDto: prost::Message + Default,
        Dto: TryFromProtobuf<ProstDto>,
    {
        let encoded_len = varint::read_usize(&mut io)
            .await
            .map_err(Into::<std::io::Error>::into)?;

        let encoded_len = match encoded_len {
            Some(len) => len,
            None => return Ok(None),
        };

        if encoded_len > max_buf_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Encoded length {} exceeds the maximum buffer size {}",
                    encoded_len, max_buf_size
                ),
            ));
        }

        let mut buf = vec![0u8; encoded_len];
        io.read_exact(&mut buf).await?;

        let prost_dto = ProstDto::decode(buf.as_ref())?;
        let dto = Dto::try_from_protobuf(prost_dto, std::any::type_name::<ProstDto>())?;
        Ok(Some(dto))
    }

    async fn encode<Writer, ProstDto, Dto>(io: &mut Writer, dto: Dto) -> std::io::Result<()>
    where
        Writer: AsyncWrite + Unpin + Send,
        ProstDto: prost::Message,
        Dto: ToProtobuf<ProstDto>,
    {
        let data = dto.to_protobuf().encode_length_delimited_to_vec();
        io.write_all(&data).await?;
        io.close().await?;
        Ok(())
    }

    mod varint {
        use futures::io::{AsyncRead, AsyncReadExt};
        use std::io;
        use unsigned_varint::{decode, io::ReadError};

        /// A version of `unsigned_varint::aio::read_usize` that returns `Ok(None)` if the reader is empty.
        pub async fn read_usize<R: AsyncRead + Unpin>(
            mut reader: R,
        ) -> Result<Option<usize>, ReadError> {
            let mut b = unsigned_varint::encode::usize_buffer();

            let n = reader.read(&mut b[0..1]).await?;
            if n == 0 {
                return Ok(None);
            }

            for i in 1..b.len() {
                let n = reader.read(&mut b[i..i + 1]).await?;
                if n == 0 {
                    return Err(ReadError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                if decode::is_last(b[i]) {
                    return Ok(Some(decode::usize(&b[..=i])?.0));
                }
            }
            Err(decode::Error::Overflow)?
        }
    }
}
