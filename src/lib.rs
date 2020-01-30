#![allow(non_snake_case)]
pub mod bitcoin;
pub mod grin;

use blake2::{Blake2b, Digest};
use rand::Rng;

// TODO: Do we need inputs, outputs and change outputs for bitcoin?
// TODO: Encode direction of swap here
pub struct SetupParameters {
    grin_amount: u64,
    bitcoin_amount: u64,
    grin_fee: u64, // for simplicity we don't model separate fee values for different transactions
    bitcoin_fee: u64,
    grin_expiry: u64,    // block height
    bitcoin_expiry: u32, // absolute timestamp
}

// TODO: Figure out what to do with bulletproof keys, if anything. For now,
// ignore them since we don't know how we are gonna tackle them
pub struct Alice0 {
    // Grin
    x_grin: grin::KeyPair,
    r_grin_fund: grin::KeyPair,
    r_grin_redeem: grin::KeyPair,
    r_grin_refund: grin::KeyPair,
    offset_fund: grin::SecretKey,
    offset_redeem: grin::SecretKey,
    offset_refund: grin::SecretKey,
    // Bitcoin
    x_bitcoin: bitcoin::KeyPair,
}

pub struct Message0(Vec<u8>);

impl Alice0 {
    pub fn new() -> (Self, Message0) {
        let x_grin = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let r_grin_fund = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_grin_redeem = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_grin_refund = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let offset_fund =
            grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>()).secret_key;
        let offset_redeem =
            grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>()).secret_key;
        let offset_refund =
            grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>()).secret_key;

        let x_bitcoin = bitcoin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let state = Alice0 {
            x_grin: x_grin.clone(),
            r_grin_fund: r_grin_fund.clone(),
            r_grin_redeem: r_grin_redeem.clone(),
            r_grin_refund: r_grin_refund.clone(),
            offset_fund: offset_fund.clone(),
            offset_redeem: offset_redeem.clone(),
            offset_refund: offset_refund.clone(),
            x_bitcoin: x_bitcoin.clone(),
        };

        let mut hasher = Blake2b::new();

        hasher = hasher.chain(x_grin.public_key.0);
        hasher = hasher.chain(r_grin_fund.public_key.0);
        hasher = hasher.chain(r_grin_redeem.public_key.0);
        hasher = hasher.chain(r_grin_refund.public_key.0);
        hasher = hasher.chain(offset_fund.0);
        hasher = hasher.chain(offset_redeem.0);
        hasher = hasher.chain(offset_refund.0);
        hasher = hasher.chain(x_bitcoin.public_key.0);

        let message = Message0(hasher.result().as_slice().to_vec());

        (state, message)
    }

    pub fn receive(self, message1: Message1) -> (Alice1, Message2) {
        let state = Alice1 {
            x_grin: self.x_grin,
            r_grin_fund: self.r_grin_fund,
            r_grin_redeem: self.r_grin_redeem,
            r_grin_refund: self.r_grin_refund,
            offset_fund: self.offset_fund,
            offset_redeem: self.offset_redeem,
            offset_refund: self.offset_refund,
            x_bitcoin: self.x_bitcoin,
            X_grin_bob: message1.X_grin_bob,
            R_grin_fund_bob: message1.R_grin_fund_bob,
            R_grin_redeem_bob: message1.R_grin_redeem_bob,
            R_grin_refund_bob: message1.R_grin_refund_bob,
            X_bitcoin_bob: message1.X_bitcoin_bob,
        };

        // TODO: Include first phase of signing in this message. It should depend on
        // whether we are doing grin-btc or btc-grin
        let message = Message2 {
            X_grin_alice: state.x_grin.public_key,
            R_grin_fund_alice: state.r_grin_fund.public_key,
            R_grin_redeem_alice: state.r_grin_redeem.public_key,
            R_grin_refund_alice: state.r_grin_refund.public_key,
            offset_fund: state.offset_fund.clone(),
            offset_redeem: state.offset_redeem.clone(),
            offset_refund: state.offset_refund.clone(),
            X_bitcoin_alice: state.x_bitcoin.public_key,
        };

        (state, message)
    }
}

pub struct Bob0 {
    // Grin
    x_grin: grin::KeyPair,
    r_grin_fund: grin::KeyPair,
    r_grin_redeem: grin::KeyPair,
    r_grin_refund: grin::KeyPair,
    // Bitcoin
    x_bitcoin: bitcoin::KeyPair,
    // Alice's commitment
    alice_commit: Vec<u8>,
}

pub struct Message1 {
    X_grin_bob: grin::PublicKey,
    R_grin_fund_bob: grin::PublicKey,
    R_grin_redeem_bob: grin::PublicKey,
    R_grin_refund_bob: grin::PublicKey,
    X_bitcoin_bob: bitcoin::PublicKey,
}

impl Bob0 {
    pub fn new(message0: Message0) -> (Bob0, Message1) {
        let x_grin = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let r_grin_fund = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_grin_redeem = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_grin_refund = grin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let x_bitcoin = bitcoin::KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let alice_commit = message0.0;

        let state = Bob0 {
            x_grin: x_grin.clone(),
            r_grin_fund: r_grin_fund.clone(),
            r_grin_redeem: r_grin_redeem.clone(),
            r_grin_refund: r_grin_refund.clone(),
            x_bitcoin: x_bitcoin.clone(),
            alice_commit,
        };

        let message = Message1 {
            X_grin_bob: x_grin.public_key,
            R_grin_fund_bob: r_grin_fund.public_key,
            R_grin_redeem_bob: r_grin_redeem.public_key,
            R_grin_refund_bob: r_grin_refund.public_key,
            X_bitcoin_bob: x_bitcoin.public_key,
        };

        (state, message)
    }

    pub fn receive(self, message2: Message2) -> Bob1 {
        let mut hasher = Blake2b::new();

        hasher = hasher.chain(message2.X_grin_alice.0);
        hasher = hasher.chain(message2.R_grin_fund_alice.0);
        hasher = hasher.chain(message2.R_grin_redeem_alice.0);
        hasher = hasher.chain(message2.R_grin_refund_alice.0);
        hasher = hasher.chain(message2.offset_fund.clone());
        hasher = hasher.chain(message2.offset_redeem.clone());
        hasher = hasher.chain(message2.offset_refund.clone());
        hasher = hasher.chain(message2.X_bitcoin_alice.0);

        assert_eq!(hasher.result().as_slice().to_vec(), self.alice_commit);

        Bob1 {
            x_grin: self.x_grin,
            r_grin_fund: self.r_grin_fund,
            r_grin_redeem: self.r_grin_redeem,
            r_grin_refund: self.r_grin_refund,
            x_bitcoin: self.x_bitcoin,
            X_grin_alice: message2.X_grin_alice,
            R_grin_fund_alice: message2.R_grin_fund_alice,
            R_grin_redeem_alice: message2.R_grin_redeem_alice,
            R_grin_refund_alice: message2.R_grin_refund_alice,
            X_bitcoin_alice: message2.X_bitcoin_alice,
            offset_fund: message2.offset_fund,
            offset_redeem: message2.offset_redeem,
            offset_refund: message2.offset_refund,
        }
    }
}

pub struct Alice1 {
    // Grin
    x_grin: grin::KeyPair,
    r_grin_fund: grin::KeyPair,
    r_grin_redeem: grin::KeyPair,
    r_grin_refund: grin::KeyPair,
    offset_fund: grin::SecretKey,
    offset_redeem: grin::SecretKey,
    offset_refund: grin::SecretKey,
    // Bitcoin
    x_bitcoin: bitcoin::KeyPair,
    // Bob's public keys
    X_grin_bob: grin::PublicKey,
    R_grin_fund_bob: grin::PublicKey,
    R_grin_redeem_bob: grin::PublicKey,
    R_grin_refund_bob: grin::PublicKey,
    X_bitcoin_bob: bitcoin::PublicKey,
}

pub struct Message2 {
    X_grin_alice: grin::PublicKey,
    R_grin_fund_alice: grin::PublicKey,
    R_grin_redeem_alice: grin::PublicKey,
    R_grin_refund_alice: grin::PublicKey,
    offset_fund: grin::SecretKey,
    offset_redeem: grin::SecretKey,
    offset_refund: grin::SecretKey,
    X_bitcoin_alice: bitcoin::PublicKey,
}

pub struct Bob1 {
    // Grin
    x_grin: grin::KeyPair,
    r_grin_fund: grin::KeyPair,
    r_grin_redeem: grin::KeyPair,
    r_grin_refund: grin::KeyPair,
    // Bitcoin
    x_bitcoin: bitcoin::KeyPair,
    // Alice's public keys
    X_grin_alice: grin::PublicKey,
    R_grin_fund_alice: grin::PublicKey,
    R_grin_redeem_alice: grin::PublicKey,
    R_grin_refund_alice: grin::PublicKey,
    X_bitcoin_alice: bitcoin::PublicKey,
    // Grin offsets generated by Alice
    offset_fund: grin::SecretKey,
    offset_redeem: grin::SecretKey,
    offset_refund: grin::SecretKey,
}
