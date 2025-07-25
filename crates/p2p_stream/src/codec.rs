// Equilibrium Labs: This work is an extension of libp2p's request-response
// protocol, hence the original copyright notice is included below.
//
//
// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::io;

use futures::prelude::*;

/// A `Codec` defines the request and response types
/// for a request/streaming-response [`Behaviour`](crate::Behaviour) protocol or
/// protocol family and how they are encoded / decoded on an I/O stream.
pub trait Codec {
    /// The type of protocol(s) or protocol versions being negotiated.
    type Protocol: AsRef<str> + Send + Sync + Clone;
    /// The type of inbound and outbound requests.
    type Request: Send;
    /// The type of inbound and outbound responses.
    type Response: Send;

    /// Reads a request from the given I/O stream according to the
    /// negotiated protocol.
    fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send;

    /// Reads a response from the given I/O stream according to the
    /// negotiated protocol.
    fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send;

    /// Writes a request to the given I/O stream according to the
    /// negotiated protocol.
    fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send;

    /// Writes a response to the given I/O stream according to the
    /// negotiated protocol.
    fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send;
}
