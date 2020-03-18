use crate::{
    grin::{
        action, bulletproof, normalize_redeem_keys_alice, EncryptedSignature, Funder0, Funder1,
        Funder2, FunderSecret, KeyPair, Offer, PKs, Redeemer0, Redeemer1, Redeemer2,
        RedeemerSecret, RedeemerSigs, SpecialOutputs,
    },
    PublicKey,
};
use std::convert::TryInto;

#[derive(Clone)]
pub struct AliceFunder0 {
    pub common: Funder0,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceFunder0 {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        secret_init: FunderSecret,
    ) -> anyhow::Result<Self> {
        let common = Funder0::new(offer, special_outputs, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
        })
    }

    pub fn transition(
        mut self,
        mut PKs_other: PKs,
        mut y: &mut KeyPair,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<AliceFunder1> {
        normalize_redeem_keys_alice(
            &mut self.common.SKs_self.r_redeem,
            &mut PKs_other.R_redeem,
            &mut y,
        )?;

        Ok(AliceFunder1(Funder1 {
            offer: self.common.offer,
            special_outputs: self.common.special_outputs,
            secret_init: self.common.secret_init,
            SKs_self: self.common.SKs_self,
            PKs_other,
            bulletproof_round_1_self: self.bulletproof_round_1_self,
            bulletproof_round_1_other,
        }))
    }
}

pub struct AliceFunder1(pub Funder1);

impl AliceFunder1 {
    pub fn transition(
        self,
        redeemer_sigs: RedeemerSigs,
        y: &KeyPair,
        bulletproof_round_2_other: bulletproof::Round2,
    ) -> anyhow::Result<(AliceFunder2, EncryptedSignature)> {
        let (state, redeem_encsig) =
            self.0
                .transition(redeemer_sigs, &y.public_key, bulletproof_round_2_other)?;

        Ok((AliceFunder2(state), redeem_encsig))
    }
}

pub struct AliceFunder2(pub Funder2);

#[derive(Clone)]
pub struct AliceRedeemer0 {
    pub common: Redeemer0,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceRedeemer0 {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        secret_init: RedeemerSecret,
    ) -> anyhow::Result<Self> {
        let common = Redeemer0::new(offer, special_outputs, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
        })
    }

    pub fn transition(
        mut self,
        mut PKs_other: PKs,
        mut y: &mut KeyPair,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<(AliceRedeemer1, RedeemerSigs, bulletproof::Round2)> {
        normalize_redeem_keys_alice(
            &mut self.common.SKs_self.r_redeem,
            &mut PKs_other.R_redeem,
            &mut y,
        )?;

        let (state, redeemer_sigs, bulletproof_round_2_self) = Redeemer1::new(
            self.common,
            self.bulletproof_round_1_self.clone(),
            bulletproof_round_1_other.clone(),
            PKs_other,
            y.public_key,
        )?;

        Ok((
            AliceRedeemer1 {
                common: state,
                bulletproof_round_1_self: self.bulletproof_round_1_self,
                bulletproof_round_1_other,
            },
            redeemer_sigs,
            bulletproof_round_2_self,
        ))
    }
}

pub struct AliceRedeemer1 {
    pub common: Redeemer1,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl AliceRedeemer1 {
    pub fn transition(
        self,
        y: KeyPair,
        redeem_encsig: EncryptedSignature,
    ) -> anyhow::Result<AliceRedeemer2> {
        let Redeemer2 {
            encrypted_redeem_action,
        } = self.common.transition(y.public_key, redeem_encsig)?;

        let redeem_action = encrypted_redeem_action.decrypt(&y)?;

        Ok(AliceRedeemer2 { redeem_action })
    }
}

pub struct AliceRedeemer2 {
    pub redeem_action: action::Redeem,
}

impl Into<Vec<PublicKey>> for AliceFunder0 {
    fn into(self) -> Vec<PublicKey> {
        let PKs: PKs = self.common.SKs_self.into();
        vec![PKs.X, PKs.R_fund, PKs.R_redeem, PKs.R_refund]
    }
}

impl Into<Vec<PublicKey>> for AliceRedeemer0 {
    fn into(self) -> Vec<PublicKey> {
        let PKs: PKs = self.common.SKs_self.into();
        vec![PKs.X, PKs.R_fund, PKs.R_redeem, PKs.R_refund]
    }
}

impl TryInto<PKs> for Vec<PublicKey> {
    type Error = anyhow::Error;
    fn try_into(self) -> anyhow::Result<PKs> {
        Ok(PKs {
            X: self[0],
            R_fund: self[1],
            R_redeem: self[2],
            R_refund: self[3],
        })
    }
}
