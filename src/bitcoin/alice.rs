use crate::{
    bitcoin::{
        action, BaseParameters, EncryptedSignature, Funder0, Funder1, Funder2, PKs, Redeemer0,
        Redeemer1, Signature,
    },
    keypair::KeyPair,
};

pub struct AliceFunder0(pub Funder0);

impl AliceFunder0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Funder0::new(base_parameters))
    }
}

pub struct AliceFunder1(pub Funder1);

pub struct AliceFunder2(pub Funder2);

pub struct AliceRedeemer0(pub Redeemer0);

impl AliceRedeemer0 {
    pub fn new(base_parameters: BaseParameters) -> Self {
        Self(Redeemer0::new(base_parameters))
    }

    pub fn transition(self, PKs_other: PKs) -> (AliceRedeemer1, Signature) {
        let (state, redeemer_refund_sig) =
            Redeemer1::new(self.0.base_parameters, self.0.SKs_self, PKs_other);

        (AliceRedeemer1(state), redeemer_refund_sig)
    }
}

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
