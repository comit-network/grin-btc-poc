use crate::grin::{
    action, bulletproof, normalize_redeem_keys_bob, BaseParameters, EncryptedSignature, Funder0,
    Funder1, Funder2, FunderSecret, PKs, PublicKey, Redeemer0, Redeemer1, Redeemer2,
    RedeemerSecret, RedeemerSigs,
};

#[derive(Clone)]
pub struct BobFunder0 {
    pub common: Funder0,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl BobFunder0 {
    pub fn new(
        base_parameters: BaseParameters,
        secret_init: FunderSecret,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<Self> {
        let common = Funder0::new(base_parameters, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
            bulletproof_round_1_other,
        })
    }
}

pub struct BobFunder1(pub Funder1);

pub struct BobFunder2(pub Funder2);

#[derive(Clone)]
pub struct BobRedeemer0 {
    pub common: Redeemer0,
    pub bulletproof_round_1_self: bulletproof::Round1,
    pub bulletproof_round_1_other: bulletproof::Round1,
}

impl BobRedeemer0 {
    pub fn new(
        base_parameters: BaseParameters,
        secret_init: RedeemerSecret,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<Self> {
        let common = Redeemer0::new(base_parameters, secret_init);
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
