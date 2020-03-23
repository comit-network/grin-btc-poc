use crate::{
    bitcoin::{
        action, sign::FunderActions, wallet_outputs::WalletOutputs, EncryptedSignature, Funder0,
        Funder1, Offer, PKs, Redeemer0, Redeemer1, Signature,
    },
    commit::CoinTossingKeys,
    KeyPair,
};
use std::convert::TryInto;

#[derive(Clone)]
pub struct AliceFunder0(pub Funder0);

impl AliceFunder0 {
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        Self(Funder0::new(offer, wallet_outputs))
    }

    pub fn transition(self, PKs_other: PKs) -> AliceFunder1 {
        AliceFunder1(self.0.transition(PKs_other))
    }
}

pub struct AliceFunder1(pub Funder1);

impl AliceFunder1 {
    pub fn transition(
        self,
        redeemer_refund_sig: Signature,
        y: &KeyPair,
    ) -> anyhow::Result<(AliceFunder2, EncryptedSignature)> {
        let (FunderActions { fund, refund }, redeem_encsig) =
            self.0.sign(&y.public_key, redeemer_refund_sig)?;

        Ok((
            AliceFunder2 {
                fund_action: fund,
                refund_action: refund,
            },
            redeem_encsig,
        ))
    }
}

pub struct AliceFunder2 {
    pub fund_action: action::Fund,
    pub refund_action: action::Refund,
}

#[derive(Clone)]
pub struct AliceRedeemer0(pub Redeemer0);

impl AliceRedeemer0 {
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        Self(Redeemer0::new(offer, wallet_outputs))
    }

    pub fn transition(self, PKs_other: PKs) -> anyhow::Result<(AliceRedeemer1, Signature)> {
        let (state, redeemer_refund_sig) = self.0.transition(PKs_other)?;

        Ok((AliceRedeemer1(state), redeemer_refund_sig))
    }
}

#[derive(Clone)]
pub struct AliceRedeemer1(pub Redeemer1);

impl AliceRedeemer1 {
    pub fn transition(
        self,
        redeem_encsig: EncryptedSignature,
        y: &KeyPair,
    ) -> anyhow::Result<AliceRedeemer2> {
        let encrypted_redeem_action = action::EncryptedRedeem::new(
            &self.0.offer,
            &self.0.wallet_outputs,
            &self.0.SKs_self,
            &self.0.PKs_other,
            redeem_encsig,
        )?;
        let redeem_action = encrypted_redeem_action.decrypt(&y);

        Ok(AliceRedeemer2 { redeem_action })
    }
}

pub struct AliceRedeemer2 {
    pub redeem_action: action::Redeem,
}

impl Into<CoinTossingKeys> for AliceFunder0 {
    fn into(self) -> CoinTossingKeys {
        let PKs: PKs = self.0.SKs_self.into();
        vec![PKs.X]
    }
}

impl Into<CoinTossingKeys> for AliceRedeemer0 {
    fn into(self) -> CoinTossingKeys {
        let PKs: PKs = self.0.SKs_self.into();
        vec![PKs.X]
    }
}

impl TryInto<PKs> for CoinTossingKeys {
    type Error = anyhow::Error;
    fn try_into(self) -> anyhow::Result<PKs> {
        Ok(PKs { X: self[0] })
    }
}
