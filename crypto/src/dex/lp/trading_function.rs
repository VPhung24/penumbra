use penumbra_proto::{core::dex::v1alpha1 as pb, Protobuf};
use serde::{Deserialize, Serialize};

use crate::Amount;

/// The data describing a trading function.
///
/// This implicitly treats the trading function as being between assets 1 and 2,
/// without specifying what those assets are, to avoid duplicating data (each
/// asset ID alone is twice the size of the trading function).
///
/// The trading function is `phi(R) = p*R_1 + q*R_2`.
/// This is used as a CFMM with constant `k` and fee `fee` (gamma).
///
/// NOTE: the use of floats here is a placeholder ONLY, so we can stub out the implementation,
/// and then decide what type of fixed-point, deterministic arithmetic should be used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "pb::TradingFunction", into = "pb::TradingFunction")]

pub struct TradingFunction {
    pub fee: u32,
    pub p: Amount,
    pub q: Amount,
}

impl Protobuf<pb::TradingFunction> for TradingFunction {}

impl TryFrom<pb::TradingFunction> for TradingFunction {
    type Error = anyhow::Error;

    fn try_from(value: pb::TradingFunction) -> Result<Self, Self::Error> {
        Ok(Self {
            fee: value.fee,
            p: value
                .p
                .ok_or_else(|| anyhow::anyhow!("missing p"))?
                .try_into()?,
            q: value
                .q
                .ok_or_else(|| anyhow::anyhow!("missing q"))?
                .try_into()?,
        })
    }
}

impl From<TradingFunction> for pb::TradingFunction {
    fn from(value: TradingFunction) -> Self {
        Self {
            fee: value.fee,
            p: Some(value.p.into()),
            q: Some(value.q.into()),
        }
    }
}
