use core::error::Error;
use std::borrow::Cow;

use either::Either;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::protocol::Protocol;

pub trait Transport {
    type Error: Error;

    #[expect(async_fn_in_trait, reason = "Should be fine")]
    async fn send(
        &self,
        request: TransportRequest<'_>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
#[non_exhaustive]
pub struct TransportRequest<'a> {
    pub protocol: Cow<'a, str>,
    pub network_id: Cow<'a, str>,
    pub contract_id: Cow<'a, str>,
    pub operation: Operation<'a>,
}

impl<'a> TransportRequest<'a> {
    #[must_use]
    pub const fn new(
        protocol: Cow<'a, str>,
        network_id: Cow<'a, str>,
        contract_id: Cow<'a, str>,
        operation: Operation<'a>,
    ) -> Self {
        Self {
            protocol,
            network_id,
            contract_id,
            operation,
        }
    }
}

#[derive(Debug, Error)]
pub enum EitherError<L, R> {
    #[error(transparent)]
    Left(L),
    #[error(transparent)]
    Right(R),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}

impl<L: Transport, R: Transport> Transport for Either<L, R> {
    type Error = EitherError<L::Error, R::Error>;

    async fn send(
        &self,
        request: TransportRequest<'_>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Left(left) => left.send(request, payload).await.map_err(EitherError::Left),
            Self::Right(right) => right
                .send(request, payload)
                .await
                .map_err(EitherError::Right),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[expect(clippy::exhaustive_enums, reason = "Considered to be exhaustive")]
pub enum Operation<'a> {
    Read { method: Cow<'a, str> },
    Write { method: Cow<'a, str> },
}

pub trait AssociatedTransport: Transport {
    type Protocol: Protocol;

    #[inline]
    #[must_use]
    fn protocol() -> &'static str {
        Self::Protocol::PROTOCOL
    }
}

#[expect(clippy::exhaustive_structs, reason = "this is exhaustive")]
#[derive(Debug, Clone)]
pub struct Both<L, R> {
    pub left: L,
    pub right: R,
}

impl<L, R> Transport for Both<L, R>
where
    L: AssociatedTransport,
    R: AssociatedTransport,
{
    type Error = EitherError<L::Error, R::Error>;

    async fn send(
        &self,
        request: TransportRequest<'_>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        if request.protocol == L::protocol() {
            self.left
                .send(request, payload)
                .await
                .map_err(EitherError::Left)
        } else if request.protocol == R::protocol() {
            self.right
                .send(request, payload)
                .await
                .map_err(EitherError::Right)
        } else {
            return Err(EitherError::UnsupportedProtocol(
                request.protocol.into_owned(),
            ));
        }
    }
}
