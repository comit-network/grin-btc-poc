#![allow(non_snake_case)]

pub mod alice;
pub mod bitcoin;
pub mod bob;
pub mod commit;
pub mod dleq;
pub mod ecdsa;
pub mod execute;
pub mod grin;
pub mod keypair;
pub mod look_for;
pub mod messages;
pub mod schnorr;

pub use execute::Execute;
pub use keypair::{KeyPair, PublicKey, SecretKey};
pub use look_for::LookFor;

pub trait Hash {
    fn hash(&self) -> [u8; 64];
}
