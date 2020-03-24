use crate::{
    bitcoin::{
        action, event, sign::FunderActions, wallet_outputs::WalletOutputs, EncryptedSignature,
        Funder0, Funder1, Offer, PKs, PublicKey, Redeemer0, Redeemer1, Signature,
    },
    ecdsa::{self, RecoveryKey},
};

#[derive(Clone)]
pub struct BobFunder0(pub Funder0);

impl BobFunder0 {
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        Self(Funder0::new(offer, wallet_outputs))
    }

    pub fn transition(
        self,
        PKs_other: PKs,
        redeemer_refund_sig: Signature,
        Y: &PublicKey,
    ) -> anyhow::Result<(BobFunder1, EncryptedSignature)> {
        let state = self.0.transition(PKs_other);

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
            &self.common.offer,
            &self.common.wallet_outputs,
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
    /// Run key generation for the redeemer of bitcoin.
    pub fn new(offer: Offer, wallet_outputs: WalletOutputs) -> Self {
        // Just run key generation for the funder of bitcoin. Nothing else.
        Self(Redeemer0::new(offer, wallet_outputs))
    }

    pub fn transition(self, PKs_other: PKs) -> anyhow::Result<(BobRedeemer1, Signature)> {
        let (state, redeemer_refund_sig) = self.0.transition(PKs_other)?;

        Ok((BobRedeemer1(state), redeemer_refund_sig))
    }
}

pub struct BobRedeemer1(pub Redeemer1);

impl BobRedeemer1 {
    pub fn transition(self, redeem_encsig: EncryptedSignature) -> anyhow::Result<BobRedeemer2> {
        let encrypted_redeem_action = action::EncryptedRedeem::new(
            &self.0.offer,
            &self.0.wallet_outputs,
            &self.0.SKs_self,
            &self.0.PKs_other,
            redeem_encsig,
        )?;

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
        self.0.SKs_self.into()
    }
}

impl Into<PKs> for BobRedeemer0 {
    fn into(self) -> PKs {
        self.0.SKs_self.into()
    }
}
