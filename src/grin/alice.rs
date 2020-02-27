use crate::grin::{
    bulletproof, normalize_redeem_keys_alice, BaseParameters, EncryptedSignature, Funder0, Funder1,
    Funder2, FunderSecret, KeyPair, PKs, Redeemer0, Redeemer1, Redeemer2, RedeemerSecret,
    RedeemerSigs,
};

#[derive(Clone)]
pub struct AliceFunder0 {
    pub common: Funder0,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceFunder0 {
    pub fn new(base_parameters: BaseParameters, secret_init: FunderSecret) -> anyhow::Result<Self> {
        let common = Funder0::new(base_parameters, secret_init);
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
            base_parameters: self.common.base_parameters,
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

pub struct AliceRedeemer0 {
    pub common: Redeemer0,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceRedeemer0 {
    pub fn new(
        base_parameters: BaseParameters,
        secret_init: RedeemerSecret,
    ) -> anyhow::Result<Self> {
        let common = Redeemer0::new(base_parameters, secret_init);
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_round_1_self,
        })
    }
}

pub struct AliceRedeemer1(pub Redeemer1);

pub struct AliceRedeemer2(pub Redeemer2);
