use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response::RequestResponseCodec;

#[derive(Debug, Clone)]
pub struct BlockSyncProtocol();

pub const PROTOCOL_NAME: &[u8] = "/core/blocks-sync/1".as_bytes();

impl ProtocolName for BlockSyncProtocol {
    fn protocol_name(&self) -> &[u8] {
        PROTOCOL_NAME
    }
}

#[derive(Clone)]
pub struct BlockSyncCodec();

#[async_trait]
impl RequestResponseCodec for BlockSyncCodec {
    type Protocol = BlockSyncProtocol;
    type Request = p2p_proto::sync::Request;
    type Response = p2p_proto::sync::Response;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;

        if vec.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        let request = Self::Request::from_protobuf_encoding(&vec)?;

        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        _: &BlockSyncProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 500_000_000).await?; // update transfer maximum

        if vec.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        let response = Self::Response::from_protobuf_encoding(&vec)?;

        Ok(response)
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
        let request = request.into_protobuf_encoding()?;
        write_length_prefixed(io, &request).await?;
        io.close().await?;

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
        let response = response.into_protobuf_encoding()?;
        write_length_prefixed(io, &response).await?;
        io.close().await?;

        Ok(())
    }
}
