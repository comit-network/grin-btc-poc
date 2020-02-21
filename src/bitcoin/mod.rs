use crate::keypair::{KeyPair, PublicKey};

pub mod action;
pub mod sign;
pub mod transaction;

pub use crate::ecdsa::EncryptedSignature;
pub use ::bitcoin::{
    hashes::Hash, util::bip143::SighashComponents, Address, OutPoint, Transaction,
};
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
