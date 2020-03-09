use crate::bitcoin::sign::FunderActions;
use crate::{
    bitcoin::{
        action, BaseParameters, EncryptedSignature, Funder0, Funder1, PKs, Redeemer0, Redeemer1,
        Signature,
    },
    KeyPair, PublicKey,
};
use std::convert::TryInto;

#[derive(Clone)]
pub struct AliceFunder0(pub Funder0);

impl AliceFunder0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Funder0::new(base_parameters))
    }

    pub fn transition(self, PKs_other: PKs) -> AliceFunder1 {
        AliceFunder1(Funder1::new(self.0, PKs_other))
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
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Redeemer0::new(base_parameters))
    }

    pub fn transition(self, PKs_other: PKs) -> (AliceRedeemer1, Signature) {
        let (state, redeemer_refund_sig) = self.0.transition(PKs_other);

        (AliceRedeemer1(state), redeemer_refund_sig)
    }
}

#[derive(Clone)]
pub struct AliceRedeemer1(pub Redeemer1);

impl AliceRedeemer1 {
    pub fn transition(self, redeem_encsig: EncryptedSignature, y: &KeyPair) -> AliceRedeemer2 {
        let encrypted_redeem_action = action::EncryptedRedeem::new(
            &self.0.base_parameters,
            &self.0.SKs_self,
            &self.0.PKs_other,
            redeem_encsig,
        );
        let redeem_action = encrypted_redeem_action.decrypt(&y);

        AliceRedeemer2 { redeem_action }
    }
}

pub struct AliceRedeemer2 {
    pub redeem_action: action::Redeem,
}

impl Into<Vec<PublicKey>> for AliceFunder0 {
    fn into(self) -> Vec<PublicKey> {
        let PKs: PKs = self.0.SKs_self.into();
        vec![PKs.X]
    }
}

impl Into<Vec<PublicKey>> for AliceRedeemer0 {
    fn into(self) -> Vec<PublicKey> {
        let PKs: PKs = self.0.SKs_self.into();
        vec![PKs.X]
    }
}

impl TryInto<PKs> for Vec<PublicKey> {
    type Error = anyhow::Error;
    fn try_into(self) -> anyhow::Result<PKs> {
        Ok(PKs { X: self[0] })
    }
}