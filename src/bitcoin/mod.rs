use crate::keypair::{KeyPair, PublicKey};
use rand::Rng;

pub mod action;
pub mod rpc;
pub mod sign;
pub mod transaction;

pub use crate::ecdsa::EncryptedSignature;
pub use ::bitcoin::{
    hashes::Hash, network::constants::Network, util::bip143::SighashComponents,
    util::key::PublicKey as BitcoinPublicKey, Address, OutPoint, SigHashType, Transaction,
};
pub use secp256k1zkp::Signature;

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
}

impl SKs {
    pub fn keygen() -> SKs {
        let x = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        SKs { x }
    }

    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key.clone(),
        }
    }
}

pub struct PKs {
    pub X: PublicKey,
}
