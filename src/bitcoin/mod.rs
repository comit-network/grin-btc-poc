use crate::keypair::{KeyPair, PublicKey};

pub mod action;
pub mod client;
pub mod event;
pub mod node;
pub mod sign;
pub mod transaction;
pub mod wallet;

pub use crate::ecdsa::EncryptedSignature;
pub use ::bitcoin::{
    blockdata::transaction::TxOut, network::constants::Network,
    util::key::PublicKey as BitcoinPublicKey, Address, OutPoint, Script, Transaction,
};
pub use client::Client;
pub use node::{Node, Wallets};
pub use secp256k1zkp::Signature;

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
}

impl SKs {
    pub fn keygen() -> SKs {
        let x = KeyPair::new_random();

        SKs { x }
    }

    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key,
        }
    }
}

pub struct PKs {
    pub X: PublicKey,
}
