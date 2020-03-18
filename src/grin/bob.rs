use crate::{
    grin::{
        action, bulletproof, event, normalize_redeem_keys_bob, EncryptedSignature, Funder0,
        Funder1, FunderSecret, Offer, PKs, PublicKey, Redeemer0, Redeemer1, Redeemer2,
        RedeemerSecret, RedeemerSigs, SKs, SpecialOutputs,
    },
    schnorr::RecoveryKey,
};
use std::convert::TryFrom;

#[derive(Clone)]
pub struct BobFunder0 {
    pub common: Funder0,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl BobFunder0 {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        secret_init: FunderSecret,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<Self> {
        let common = Funder0::new(offer, special_outputs, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
            bulletproof_round_1_other,
        })
    }

    pub fn transition(
        self,
        PKs_other: PKs,
        redeemer_sigs: RedeemerSigs,
        Y: &PublicKey,
        bulletproof_round_2_other: bulletproof::Round2,
    ) -> anyhow::Result<(BobFunder1, EncryptedSignature)> {
        let state = Funder1 {
            offer: self.common.offer.clone(),
            special_outputs: self.common.special_outputs.clone(),
            secret_init: self.common.secret_init,
            SKs_self: self.common.SKs_self.clone(),
            PKs_other: PKs_other.clone(),
            bulletproof_round_1_self: self.bulletproof_round_1_self,
            bulletproof_round_1_other: self.bulletproof_round_1_other,
        };

        let (state, redeem_encsig) =
            state.transition(redeemer_sigs, &Y, bulletproof_round_2_other)?;

        let recovery_key = RecoveryKey::try_from(redeem_encsig)?;

        Ok((
            BobFunder1 {
                special_outputs: self.common.special_outputs,
                SKs_self: self.common.SKs_self,
                PKs_other,
                fund_action: state.fund_action,
                refund_action: state.refund_action,
                recovery_key,
            },
            redeem_encsig,
        ))
    }
}

pub struct BobFunder1 {
    special_outputs: SpecialOutputs,
    SKs_self: SKs,
    PKs_other: PKs,
    fund_action: action::Fund,
    refund_action: action::Refund,
    recovery_key: RecoveryKey,
}

impl BobFunder1 {
    pub fn transition(self) -> anyhow::Result<BobFunder2> {
        let redeem_event = event::Redeem::new(
            &self.special_outputs,
            &self.PKs_other,
            &self.SKs_self.into(),
        )?;

        Ok(BobFunder2 {
            fund_action: self.fund_action,
            refund_action: self.refund_action,
            recovery_key: self.recovery_key,
            redeem_event,
        })
    }
}

pub struct BobFunder2 {
    pub fund_action: action::Fund,
    pub refund_action: action::Refund,
    pub recovery_key: RecoveryKey,
    pub redeem_event: event::Redeem,
}

#[derive(Clone)]
pub struct BobRedeemer0 {
    pub common: Redeemer0,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl BobRedeemer0 {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        secret_init: RedeemerSecret,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<Self> {
        let common = Redeemer0::new(offer, special_outputs, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
            bulletproof_round_1_other,
        })
    }

    pub fn transition(
        mut self,
        mut PKs_other: PKs,
        mut Y: PublicKey,
    ) -> anyhow::Result<(BobRedeemer1, RedeemerSigs, bulletproof::Round2)> {
        normalize_redeem_keys_bob(
            &mut PKs_other.R_redeem,
            &mut self.common.SKs_self.r_redeem,
            &mut Y,
        )?;

        let (state, redeemer_sigs, bulletproof_round_2_self) = Redeemer1::new(
            self.common,
            self.bulletproof_round_1_self,
            self.bulletproof_round_1_other,
            PKs_other,
            Y,
        )?;

        Ok((BobRedeemer1(state), redeemer_sigs, bulletproof_round_2_self))
    }
}

pub struct BobRedeemer1(pub Redeemer1);

impl BobRedeemer1 {
    pub fn transition(
        self,
        Y: PublicKey,
        redeem_encsig: EncryptedSignature,
    ) -> anyhow::Result<BobRedeemer2> {
        let Redeemer2 {
            encrypted_redeem_action,
        } = self.0.transition(Y, redeem_encsig)?;

        Ok(BobRedeemer2 {
            encrypted_redeem_action,
        })
    }
}

pub struct BobRedeemer2 {
    pub encrypted_redeem_action: action::EncryptedRedeem,
}

impl Into<PKs> for BobFunder0 {
    fn into(self) -> PKs {
        self.common.SKs_self.into()
    }
}

impl Into<PKs> for BobRedeemer0 {
    fn into(self) -> PKs {
        self.common.SKs_self.into()
    }
}
