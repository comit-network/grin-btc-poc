use crate::{bitcoin::sign::FunderActions, KeyPair};

pub mod action;
pub mod alice;
pub mod bob;
pub mod client;
pub mod event;
pub mod keys;
pub mod node;
pub mod offer;
pub mod sign;
pub mod transaction;
pub mod wallet;
pub mod wallet_outputs;

pub use crate::{
    bitcoin::{
        alice::*,
        bob::*,
        keys::{PKs, SKs},
        offer::Offer,
        wallet_outputs::WalletOutputs,
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

#[derive(Clone)]
pub struct Funder0 {
    pub offer: Offer,
    pub wallet_outputs: WalletOutputs,
    pub SKs_self: SKs,
}

impl Funder0 {
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        let SKs_self = keygen();

        Self {
            offer,
            wallet_outputs,
            SKs_self,
        }
    }

    pub fn transition(self, PKs_other: PKs) -> Funder1 {
        Funder1 {
            offer: self.offer,
            wallet_outputs: self.wallet_outputs,
            SKs_self: self.SKs_self,
            PKs_other,
        }
    }
}

#[derive(Clone)]
pub struct Funder1 {
    pub offer: Offer,
    pub wallet_outputs: WalletOutputs,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
}

impl Funder1 {
    pub fn sign(
        self,
        Y: &PublicKey,
        redeemer_refund_sig: Signature,
    ) -> anyhow::Result<(FunderActions, EncryptedSignature)> {
        let (funder_actions, redeem_encsig) = sign::funder(
            &self.offer,
            &self.wallet_outputs,
            &self.SKs_self,
            &self.PKs_other,
            &Y,
            &redeemer_refund_sig,
        )?;

        Ok((funder_actions, redeem_encsig))
    }
}

pub struct Funder2 {
    pub fund_action: action::Fund,
    pub refund_action: action::Refund,
}

#[derive(Clone)]
pub struct Redeemer0 {
    pub offer: Offer,
    pub wallet_outputs: WalletOutputs,
    pub SKs_self: SKs,
}

impl Redeemer0 {
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        let SKs_self = keygen();

        Self {
            offer,
            wallet_outputs,
            SKs_self,
        }
    }

    pub fn transition(self, PKs_other: PKs) -> anyhow::Result<(Redeemer1, Signature)> {
        let redeemer_refund_sig = sign::redeemer(
            &self.offer,
            &self.wallet_outputs,
            &self.SKs_self,
            &PKs_other,
        )?;

        let state = Redeemer1 {
            offer: self.offer,
            wallet_outputs: self.wallet_outputs,
            SKs_self: self.SKs_self,
            PKs_other,
        };

        Ok((state, redeemer_refund_sig))
    }
}

#[derive(Clone)]
pub struct Redeemer1 {
    pub offer: Offer,
    pub wallet_outputs: WalletOutputs,
    pub SKs_self: SKs,
    pub PKs_other: PKs,
}

pub struct Redeemer2 {
    pub encrypted_redeem_action: action::EncryptedRedeem,
}

pub fn keygen() -> SKs {
    let x = KeyPair::new_random();

    SKs { x }
}
