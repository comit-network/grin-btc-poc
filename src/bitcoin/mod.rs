use crate::{bitcoin::sign::FunderActions, KeyPair};

pub mod action;
pub mod alice;
pub mod base_parameters;
pub mod bob;
pub mod client;
pub mod event;
pub mod keys;
pub mod node;
pub mod sign;
pub mod transaction;
pub mod wallet;

pub use crate::{
    bitcoin::{
        alice::*,
        base_parameters::BaseParameters,
        bob::*,
        keys::{PKs, SKs},
    },
    ecdsa::EncryptedSignature,
    PublicKey,
};
pub use ::bitcoin::{
    blockdata::transaction::TxOut, network::constants::Network,
    util::key::PublicKey as BitcoinPublicKey, Address, OutPoint, Script, Transaction,
};
pub use client::Client;
pub use node::{Node, Wallets};
pub use secp256k1zkp::Signature;

pub struct Funder0 {
    pub base_parameters: BaseParameters,
    pub SKs_self: SKs,
}

impl Funder0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        let SKs_self = keygen();

        Self {
            base_parameters,
            SKs_self,
        }
    }
}

pub struct Funder1 {
    pub base_parameters: BaseParameters,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
    pub fund_action: action::Fund,
    pub refund_action: action::Refund,
}

impl Funder1 {
    pub fn new(
        prev_state: Funder0,
        PKs_other: PKs,
        Y: &PublicKey,
        redeemer_refund_sig: Signature,
    ) -> anyhow::Result<(Funder1, EncryptedSignature)> {
        let (FunderActions { fund, refund }, redeem_encsig) = sign::funder(
            &prev_state.base_parameters,
            &prev_state.SKs_self,
            &PKs_other,
            &Y,
            &redeemer_refund_sig,
        )?;

        let state = Funder1 {
            base_parameters: prev_state.base_parameters,
            SKs_self: prev_state.SKs_self,
            PKs_other,
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

pub struct Redeemer0 {
    pub base_parameters: BaseParameters,
    pub SKs_self: SKs,
}

impl Redeemer0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        let SKs_self = keygen();

        Self {
            base_parameters,
            SKs_self,
        }
    }
}

pub struct Redeemer1 {
    pub base_parameters: BaseParameters,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
}

impl Redeemer1 {
    pub fn new(
        base_parameters: BaseParameters,
        SKs_self: SKs,
        PKs_other: PKs,
    ) -> (Self, Signature) {
        let redeemer_refund_sig = sign::redeemer(&base_parameters, &SKs_self, &PKs_other);

        let state = Self {
            base_parameters,
            SKs_self,
            PKs_other,
        };

        (state, redeemer_refund_sig)
    }
}

pub struct Redeemer2 {
    pub encrypted_redeem_action: action::EncryptedRedeem,
}

pub fn keygen() -> SKs {
    let x = KeyPair::new_random();

    SKs { x }
}
