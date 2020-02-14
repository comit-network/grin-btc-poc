use crate::{
    bitcoin::{
        transaction::{fund_transaction, redeem_transaction},
        Hash, OutPoint, PKs, SKs, SighashComponents, Signature, Transaction,
    },
    ecdsa,
    keypair::KeyPair,
    setup_parameters,
};
use secp256k1zkp::Message;

pub struct Fund {
    pub transaction: Transaction,
    pub inputs: Vec<OutPoint>,
}

pub struct Refund {
    pub transaction: Transaction,
    pub redeemer_sig: Signature,
    pub funder_sig: Signature,
}

impl Refund {
    pub fn new(transaction: Transaction, redeemer_sig: Signature, funder_sig: Signature) -> Self {
        Self {
            transaction,
            redeemer_sig,
            funder_sig,
        }
    }
}

pub struct EncryptedRedeem {
    pub transaction: Transaction,
    pub redeemer_sig: Signature,
    pub funder_encsig: ecdsa::EncryptedSignature,
}

impl EncryptedRedeem {
    pub fn new(
        init: &setup_parameters::Bitcoin,
        redeemer_SKs: &SKs,
        funder_PKs: &PKs,
        funder_encsig: ecdsa::EncryptedSignature,
    ) -> Self {
        let (fund_transaction, fund_output_script) =
            fund_transaction(&init, &redeemer_SKs.x.public_key, &funder_PKs.X);

        let redeem_transaction = redeem_transaction(&init, fund_transaction.txid());

        let redeemer_sig = {
            let redeem_digest = SighashComponents::new(&redeem_transaction).sighash_all(
                &redeem_transaction.input[0],
                &fund_output_script,
                fund_transaction.output[0].value,
            );
            let redeem_digest = Message::from_slice(&redeem_digest.into_inner())
                .expect("should not fail because it is a hash");

            redeemer_SKs.x.sign_ecdsa(&redeem_digest)
        };

        Self {
            transaction: redeem_transaction,
            redeemer_sig,
            funder_encsig,
        }
    }

    pub fn decrypt(self, y: &KeyPair) -> Redeem {
        let funder_sig = ecdsa::decsig(&y, &self.funder_encsig).into();

        Redeem {
            transaction: self.transaction,
            redeemer_sig: self.redeemer_sig,
            funder_sig,
        }
    }
}

pub struct Redeem {
    pub transaction: Transaction,
    pub redeemer_sig: Signature,
    pub funder_sig: Signature,
}
