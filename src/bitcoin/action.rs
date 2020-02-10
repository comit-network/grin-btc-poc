use crate::{
    bitcoin::{OutPoint, Signature},
    ecdsa,
};
use ::bitcoin::Transaction;

pub struct Fund {
    pub transaction: Transaction,
    pub inputs: Vec<OutPoint>,
}

pub struct Refund {
    pub transaction: Transaction,
    pub alice_signature: Signature,
    pub bob_signature: Signature,
}

impl Refund {
    pub fn new(
        transaction: Transaction,
        alice_signature: Signature,
        bob_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            alice_signature,
            bob_signature,
        }
    }
}

pub struct Redeem {
    pub transaction: Transaction,
    pub encrypted_signature: ecdsa::EncryptedSignature,
    pub signature: Signature,
}
