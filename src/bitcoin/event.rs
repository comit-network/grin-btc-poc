use crate::{
    bitcoin::{
        transaction::{fund_transaction, redeem_transaction},
        PKs,
    },
    setup_parameters,
};
use ::bitcoin::hashes::sha256d;

pub struct Redeem {
    pub txid: sha256d::Hash,
}

impl Redeem {
    pub fn new(init: &setup_parameters::Bitcoin, redeemer_PKs: &PKs, funder_PKs: &PKs) -> Self {
        let (fund_transaction, _) = fund_transaction(&init, &redeemer_PKs.X, &funder_PKs.X);
        let redeem_transaction = redeem_transaction(&init, fund_transaction.txid());

        Self {
            txid: redeem_transaction.txid(),
        }
    }
}
