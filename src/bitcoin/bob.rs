use crate::{
    bitcoin::{
        action, event, sign::FunderActions, BaseParameters, EncryptedSignature, Funder0, Funder1,
        PKs, PublicKey, Redeemer0, Redeemer1, Redeemer2, Signature,
    },
    ecdsa::{self, RecoveryKey},
};

#[derive(Clone)]
pub struct BobFunder0(pub Funder0);

impl BobFunder0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Funder0::new(base_parameters))
    }

    pub fn transition(
        self,
        PKs_other: PKs,
        redeemer_refund_sig: Signature,
        Y: &PublicKey,
    ) -> anyhow::Result<(BobFunder1, EncryptedSignature)> {
        let state = Funder1::new(self.0, PKs_other);

        let (FunderActions { fund, refund }, redeem_encsig) =
            state.clone().sign(Y, redeemer_refund_sig)?;
        let recovery_key = ecdsa::reckey(&Y, &redeem_encsig);

        Ok((
            BobFunder1 {
                common: state,
                fund_action: fund,
                refund_action: refund,
                recovery_key,
            },
            redeem_encsig,
        ))
    }
}

pub struct BobFunder1 {
    common: Funder1,
    fund_action: action::Fund,
    refund_action: action::Refund,
    recovery_key: RecoveryKey,
}

impl BobFunder1 {
    pub fn transition(self) -> anyhow::Result<BobFunder2> {
        let redeem_event = event::Redeem::new(
            &self.common.base_parameters,
            &self.common.PKs_other,
            &self.common.SKs_self.into(),
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
pub struct BobRedeemer0(pub Redeemer0);

impl BobRedeemer0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Redeemer0::new(base_parameters))
    }
}

pub struct BobRedeemer1(pub Redeemer1);

pub struct BobRedeemer2(pub Redeemer2);

impl Into<PKs> for BobFunder0 {
    fn into(self) -> PKs {
        self.0.SKs_self.into()
    }
}

impl Into<PKs> for BobRedeemer0 {
    fn into(self) -> PKs {
        self.0.SKs_self.into()
    }
}
