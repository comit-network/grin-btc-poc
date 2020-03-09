use crate::keypair::{KeyPair, Negate, PublicKey, SecretKey, XCoor, YCoor, G, SECP};
use secp256k1zkp::key::ZERO_KEY;
use sha2::{Digest, Sha256};

pub mod action;
pub mod alice;
pub mod base_parameters;
pub mod bob;
pub mod bulletproof;
pub mod event;
pub mod keys;
pub mod sign;
pub mod wallet;

pub use crate::{
    grin::{
        alice::*,
        base_parameters::BaseParameters,
        bob::*,
        keys::{PKs, SKs},
        sign::FunderActions,
        wallet::{Wallet, Wallets},
    },
    schnorr::EncryptedSignature,
};
pub use grin_core::{
    core::KernelFeatures,
    libtx::aggsig::{add_signatures, calculate_partial_sig, verify_partial_sig},
};
pub use secp256k1zkp::Signature;
pub use sign::RedeemerSigs;

#[derive(Clone)]
pub struct Funder0 {
    // TODO: Split into Offer and SpecialOutputPKs
    pub base_parameters: BaseParameters,
    pub secret_init: FunderSecret,
    pub SKs_self: SKs,
}

impl Funder0 {
    pub fn new(base_parameters: BaseParameters, secret_init: FunderSecret) -> Self {
        let SKs_self = keygen();

        Self {
            base_parameters,
            secret_init,
            SKs_self,
        }
    }
}

pub struct Funder1 {
    pub base_parameters: BaseParameters,
    pub secret_init: FunderSecret,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl Funder1 {
    pub fn transition(
        self,
        redeemer_sigs: RedeemerSigs,
        Y: &PublicKey,
        bulletproof_round_2_other: bulletproof::Round2,
    ) -> anyhow::Result<(Funder2, EncryptedSignature)> {
        let (FunderActions { fund, refund }, redeem_encsig) = sign::funder(
            &self.base_parameters,
            &self.secret_init,
            &self.SKs_self,
            &self.PKs_other,
            &Y,
            redeemer_sigs,
            &self.bulletproof_round_1_other,
            &self.bulletproof_round_1_self,
            &bulletproof_round_2_other,
        )?;

        let state = Funder2 {
            fund_action: fund,
            refund_action: refund,
        };

        Ok((state, redeem_encsig))
    }
}

pub struct Funder2 {
    pub fund_action: action::Fund,
    pub refund_action: action::Refund,
}

#[derive(Clone)]
pub struct Redeemer0 {
    pub base_parameters: BaseParameters,
    pub secret_init: RedeemerSecret,
    pub SKs_self: SKs,
}

impl Redeemer0 {
    pub fn new(base_parameters: BaseParameters, secret_init: RedeemerSecret) -> Self {
        let SKs_self = keygen();

        Self {
            base_parameters,
            secret_init,
            SKs_self,
        }
    }
}

pub struct Redeemer1 {
    pub base_parameters: BaseParameters,
    pub secret_init: RedeemerSecret,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
}

impl Redeemer1 {
    pub fn new(
        prev_state: Redeemer0,
        bulletproof_round_1_self: bulletproof::Round1,
        bulletproof_round_1_other: bulletproof::Round1,
        PKs_other: PKs,
        Y: PublicKey,
    ) -> anyhow::Result<(Self, RedeemerSigs, bulletproof::Round2)> {
        let (redeemer_sigs, bulletproof_round_2_self) = sign::redeemer(
            &prev_state.base_parameters,
            &prev_state.secret_init,
            &prev_state.SKs_self,
            &PKs_other,
            &Y,
            &bulletproof_round_1_self,
            &bulletproof_round_1_other,
        )?;

        let state = Redeemer1 {
            base_parameters: prev_state.base_parameters,
            secret_init: prev_state.secret_init,
            SKs_self: prev_state.SKs_self,
            PKs_other,
        };

        Ok((state, redeemer_sigs, bulletproof_round_2_self))
    }

    pub fn transition(
        self,
        Y: PublicKey,
        redeem_encsig: EncryptedSignature,
    ) -> anyhow::Result<Redeemer2> {
        let encrypted_redeem_action = action::EncryptedRedeem::new(
            self.base_parameters,
            self.secret_init,
            self.SKs_self,
            self.PKs_other,
            Y,
            redeem_encsig,
        )?;

        Ok(Redeemer2 {
            encrypted_redeem_action,
        })
    }
}

pub struct Redeemer2 {
    pub encrypted_redeem_action: action::EncryptedRedeem,
}

fn keygen() -> SKs {
    let x = KeyPair::new_random();

    let r_fund = KeyPair::new_random();
    let r_redeem = KeyPair::new_random();
    let r_refund = KeyPair::new_random();

    SKs {
        x,
        r_fund,
        r_redeem,
        r_refund,
    }
}

#[derive(Debug, Clone)]
pub struct FunderSecret {
    pub fund_input_key: KeyPair,
    pub refund_output_key: KeyPair,
}

impl FunderSecret {
    pub fn new_random() -> Self {
        Self {
            fund_input_key: KeyPair::new_random(),
            refund_output_key: KeyPair::new_random(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedeemerSecret {
    pub redeem_output_key: KeyPair,
}

impl RedeemerSecret {
    pub fn new_random() -> Self {
        Self {
            redeem_output_key: KeyPair::new_random(),
        }
    }
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
            let mut offsetG = *G;
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

pub fn normalize_redeem_keys_alice(
    r0: &mut KeyPair,
    R1: &mut PublicKey,
    y: &mut KeyPair,
) -> anyhow::Result<()> {
    let R = PublicKey::from_combination(&*SECP, vec![&r0.public_key, &R1, &y.public_key])?;
    let mut R_y = purerust_secp256k1::curve::Field::default();
    assert!(R_y.set_b32(&R.y_coor()));

    if !R_y.is_quad_var() {
        *r0 = r0.negate();
        *R1 = R1.negate();
        *y = y.negate();

        Ok(())
    } else {
        Ok(())
    }
}

pub fn normalize_redeem_keys_bob(
    R0: &mut PublicKey,
    r1: &mut KeyPair,
    Y: &mut PublicKey,
) -> anyhow::Result<()> {
    let R = PublicKey::from_combination(&*SECP, vec![&R0, &r1.public_key, &Y])?;
    let mut R_y = purerust_secp256k1::curve::Field::default();
    assert!(R_y.set_b32(&R.y_coor()));

    if !R_y.is_quad_var() {
        *R0 = R0.negate();
        *r1 = r1.negate();
        *Y = Y.negate();

        Ok(())
    } else {
        Ok(())
    }
}
