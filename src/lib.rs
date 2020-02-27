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

// pub trait Sign {
//     type BaseParameters;

//     type SKs;
//     type PKs;

//     type RedeemerSigs;
//     type FunderActions;
//     type EncSig;

//     fn funder(
//         init: &Self::BaseParameters,
//         funder_SKs: &Self::SKs,
//         redeemer_PKs: &Self::PKs,
//         Y: &PublicKey,
//     ) -> (Self::FunderActions, Self::EncSig);

//     fn redeemer(
//         init: &Self::BaseParameters,
//         funder_PKs: &Self::PKs,
//         redeemer_SKs: &Self::SKs,
//         Y: &PublicKey,
//     ) -> Self::RedeemerSigs;
// }
