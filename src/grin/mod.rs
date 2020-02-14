use crate::keypair::{KeyPair, Negate, PublicKey, SecretKey, XCoor, G, SECP};
use rand::Rng;
use sha2::{Digest, Sha256};

pub mod action;
pub mod sign;

pub use crate::schnorr::EncryptedSignature;
pub use grin_core::{
    core::KernelFeatures,
    libtx::aggsig::{add_signatures, calculate_partial_sig, verify_partial_sig},
};
pub use sign::GrinRedeemerSignatures;

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
    pub r_fund: KeyPair,
    pub r_redeem: KeyPair,
    pub r_refund: KeyPair,
}

impl SKs {
    pub fn keygen() -> SKs {
        let x = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let r_fund = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_redeem = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_refund = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        SKs {
            x,
            r_fund,
            r_redeem,
            r_refund,
        }
    }

    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key.clone(),
            R_fund: self.r_fund.public_key.clone(),
            R_redeem: self.r_redeem.public_key.clone(),
            R_refund: self.r_refund.public_key.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PKs {
    pub X: PublicKey,
    pub R_fund: PublicKey,
    pub R_redeem: PublicKey,
    pub R_refund: PublicKey,
}

pub fn compute_excess_pk(
    inputs: Vec<&PublicKey>,
    outputs: Vec<&PublicKey>,
    offset: Option<&SecretKey>,
) -> Result<PublicKey, ()> {
    let total = match (inputs.clone(), outputs.clone()) {
        (inputs, outputs) if inputs.is_empty() && outputs.is_empty() => return Err(()),
        (inputs, outputs) if inputs.is_empty() && !outputs.is_empty() => {
            PublicKey::from_combination(&*SECP, outputs).unwrap()
        }
        (inputs, outputs) if !inputs.is_empty() && outputs.is_empty() => {
            let negated_inputs: Vec<PublicKey> = inputs.iter().map(|i| i.negate()).collect();
            let negated_inputs: Vec<&PublicKey> = negated_inputs.iter().map(|i| i).collect();
            PublicKey::from_combination(&*SECP, negated_inputs).unwrap()
        }
        _ => {
            let negated_inputs: Vec<PublicKey> = inputs.iter().map(|i| i.negate()).collect();
            let mut total: Vec<&PublicKey> = negated_inputs.iter().map(|i| i).collect();
            total.extend(outputs);
            PublicKey::from_combination(&*SECP, total).unwrap()
        }
    };
    match offset {
        Some(offset) => {
            let mut offsetG = G.clone();
            offsetG.mul_assign(&*SECP, &offset).unwrap();
            Ok(PublicKey::from_combination(&*SECP, vec![&total, &offsetG.negate()]).unwrap())
        }
        None => Ok(total),
    }
}

pub fn compute_offset(funder_R: &PublicKey, redeemer_R: &PublicKey) -> SecretKey {
    let mut hasher = Sha256::default();

    hasher.input(&funder_R.x_coor());
    hasher.input(&redeemer_R.x_coor());

    SecretKey::from_slice(&*SECP, &hasher.result()).unwrap()
}
