use crate::keypair::{KeyPair, Negate, PublicKey, SecretKey, XCoor, G, SECP};
use secp256k1zkp::key::ZERO_KEY;
use sha2::{Digest, Sha256};

pub mod action;
pub mod bulletproof;
pub mod sign;
pub mod wallet;

pub use crate::{
    grin::wallet::{Wallet, Wallets},
    schnorr::EncryptedSignature,
};
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
    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key.clone(),
            R_fund: self.r_fund.public_key.clone(),
            R_redeem: self.r_redeem.public_key.clone(),
            R_refund: self.r_refund.public_key.clone(),
        }
    }
}

pub fn keygen() -> anyhow::Result<(SKs, bulletproof::Round1)> {
    let x = KeyPair::new_random();

    let r_fund = KeyPair::new_random();
    let r_redeem = KeyPair::new_random();
    let r_refund = KeyPair::new_random();

    let bulletproof_round_1 = bulletproof::Round1::new(&x.secret_key)?;

    Ok((
        SKs {
            x,
            r_fund,
            r_redeem,
            r_refund,
        },
        bulletproof_round_1,
    ))
}

#[derive(Debug, Clone)]
pub struct PKs {
    pub X: PublicKey,
    pub R_fund: PublicKey,
    pub R_redeem: PublicKey,
    pub R_refund: PublicKey,
}

pub fn compute_excess_sk(
    inputs: Vec<&SecretKey>,
    outputs: Vec<&SecretKey>,
    offset: Option<&SecretKey>,
) -> anyhow::Result<SecretKey> {
    let mut total = match (inputs.clone(), outputs.clone()) {
        (inputs, outputs) if inputs.is_empty() && outputs.is_empty() => {
            return Err(anyhow::anyhow!("invalid arguments"))
        }
        (inputs, outputs) if inputs.is_empty() && !outputs.is_empty() => {
            let mut total = ZERO_KEY;
            for o in outputs.iter() {
                total.add_assign(&*SECP, o)?;
            }
            total
        }
        (inputs, outputs) if !inputs.is_empty() && outputs.is_empty() => {
            let negated_inputs: Vec<SecretKey> = inputs.iter().map(|i| i.negate()).collect();
            let negated_inputs: Vec<&SecretKey> = negated_inputs.iter().map(|i| i).collect();

            let mut total = ZERO_KEY;
            for i in negated_inputs.iter() {
                total.add_assign(&*SECP, i)?;
            }
            total
        }
        _ => {
            let negated_inputs: Vec<SecretKey> = inputs.iter().map(|i| i.negate()).collect();
            let negated_inputs: Vec<&SecretKey> = negated_inputs.iter().map(|i| i).collect();

            let mut total = ZERO_KEY;
            for i in negated_inputs.iter() {
                total.add_assign(&*SECP, i)?;
            }
            for o in outputs.iter() {
                total.add_assign(&*SECP, o)?;
            }
            total
        }
    };
    match offset {
        Some(offset) => {
            total.add_assign(&*SECP, &offset.negate())?;
            Ok(total)
        }
        None => Ok(total),
    }
}

pub fn compute_excess_pk(
    inputs: Vec<&PublicKey>,
    outputs: Vec<&PublicKey>,
    offset: Option<&SecretKey>,
) -> anyhow::Result<PublicKey> {
    let total = match (inputs.clone(), outputs.clone()) {
        (inputs, outputs) if inputs.is_empty() && outputs.is_empty() => {
            return Err(anyhow::anyhow!("invalid arguments"))
        }
        (inputs, outputs) if inputs.is_empty() && !outputs.is_empty() => {
            PublicKey::from_combination(&*SECP, outputs)?
        }
        (inputs, outputs) if !inputs.is_empty() && outputs.is_empty() => {
            let negated_inputs: Vec<PublicKey> = inputs.iter().map(|i| i.negate()).collect();
            let negated_inputs: Vec<&PublicKey> = negated_inputs.iter().map(|i| i).collect();
            PublicKey::from_combination(&*SECP, negated_inputs)?
        }
        _ => {
            let negated_inputs: Vec<PublicKey> = inputs.iter().map(|i| i.negate()).collect();
            let mut total: Vec<&PublicKey> = negated_inputs.iter().map(|i| i).collect();
            total.extend(outputs);
            PublicKey::from_combination(&*SECP, total)?
        }
    };
    match offset {
        Some(offset) => {
            let mut offsetG = G.clone();
            offsetG.mul_assign(&*SECP, &offset)?;
            Ok(PublicKey::from_combination(&*SECP, vec![
                &total,
                &offsetG.negate(),
            ])?)
        }
        None => Ok(total),
    }
}

pub fn compute_offset(funder_R: &PublicKey, redeemer_R: &PublicKey) -> anyhow::Result<SecretKey> {
    let mut hasher = Sha256::default();

    hasher.input(&funder_R.x_coor());
    hasher.input(&redeemer_R.x_coor());

    Ok(SecretKey::from_slice(&*SECP, &hasher.result())?)
}
