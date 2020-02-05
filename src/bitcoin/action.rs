use crate::bitcoin::OutPoint;
use ::bitcoin::Transaction;
use secp256k1zkp::Signature;

pub struct Fund {
    pub transaction: Transaction,
    pub inputs: Vec<OutPoint>,
}

pub struct Refund {
    transaction: Transaction,
    alice_signature: Signature,
    bob_signature: Signature,
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
