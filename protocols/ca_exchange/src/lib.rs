
mod crypt_writer;
use futures::prelude::*;
use log::trace;
use pin_project::pin_project;

use std::{
    error,
    fmt::{self, Write},
    io,
    io::Error as IoError,
    num::ParseIntError,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

/// A pre-shared key, consisting of 32 bytes of random data.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PreSharedKey([u8; 32]);

impl PreSharedKey {
    /// Create a new pre shared key from raw bytes
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }
}

/// Private network configuration
#[derive(Debug, Copy, Clone)]
pub struct PnetConfig {
    /// the PreSharedKey to use for encryption
    key: PreSharedKey,
}
impl PnetConfig {
    pub fn new(key: PreSharedKey) -> Self {
        Self { key }
    }

    /// upgrade a connection to use pre shared key encryption.
    ///
    /// the upgrade works by both sides exchanging 24 byte nonces and then encrypting
    /// subsequent traffic with XSalsa20
    pub async fn handshake<TSocket>(
        self,
        mut socket: TSocket,
    ) -> Result<PnetOutput<TSocket>, PnetError>
    where
        TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        trace!("exchanging nonces");
        let mut local_nonce = [1u8; 32];
        let mut remote_nonce = [0u8; 32];
        // rand::thread_rng().fill_bytes(&mut local_nonce);
        socket
            .write_all(&local_nonce)
            .await
            .map_err(PnetError::HandshakeError)?;
        socket
            .read_exact(&mut remote_nonce)
            .await
            .map_err(PnetError::HandshakeError)?;
        trace!("remote nonce is {:?}", remote_nonce);
        // let write_cipher = XSalsa20::new(&self.key.0.into(), &local_nonce.into());
        // let read_cipher = XSalsa20::new(&self.key.0.into(), &remote_nonce.into());
        Ok(PnetOutput::new(socket))
    }
}

/// The result of a handshake. This implements AsyncRead and AsyncWrite and can therefore
/// be used as base for additional upgrades.
#[pin_project]
pub struct PnetOutput<S> {
    #[pin]
    inner: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite> PnetOutput<S> {
    fn new(inner: S) -> Self {
        Self {
            inner: inner,
            buf: Vec::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for PnetOutput<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(size)) = &result {
            trace!("read {} bytes", size);
            // this.read_cipher.apply_keystream(&mut buf[..*size]);
            trace!("data before cipher is {:?} ", buf);
        }
        result
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for PnetOutput<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Error when writing or reading private swarms
#[derive(Debug)]
pub enum PnetError {
    /// Error during handshake.
    HandshakeError(IoError),
    /// I/O error.
    IoError(IoError),
}

impl From<IoError> for PnetError {
    #[inline]
    fn from(err: IoError) -> PnetError {
        PnetError::IoError(err)
    }
}

impl error::Error for PnetError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            PnetError::HandshakeError(ref err) => Some(err),
            PnetError::IoError(ref err) => Some(err),
        }
    }
}

impl fmt::Display for PnetError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            PnetError::HandshakeError(e) => write!(f, "Handshake error: {}", e),
            PnetError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

