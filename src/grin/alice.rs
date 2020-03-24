use crate::{
    commit::CoinTossingKeys,
    grin::{
        action, bulletproof, normalize_redeem_keys_alice, EncryptedSignature, Funder0, Funder1,
        Funder2, KeyPair, Offer, PKs, Redeemer0, Redeemer1, Redeemer2, RedeemerSigs,
        SpecialOutputKeyPairsFunder, SpecialOutputKeyPairsRedeemer, SpecialOutputs,
    },
};
use std::convert::TryInto;

#[derive(Clone)]
pub struct AliceFunder0 {
    pub common: Funder0,
    pub bulletproof_common_nonce: bulletproof::CommonNonce,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceFunder0 {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        special_output_keypairs_funder: SpecialOutputKeyPairsFunder,
    ) -> anyhow::Result<Self> {
        let common = Funder0::new(offer, special_outputs, special_output_keypairs_funder);

        let bulletproof_common_nonce =
            bulletproof::CommonNonce::derive(&common.SKs_self.x.public_key)?;
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_common_nonce,
            bulletproof_round_1_self,
        })
    }

    pub fn transition(
        self,
        PKs_other: PKs,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<AliceFunder1> {
        Ok(AliceFunder1(Funder1 {
            offer: self.common.offer,
            special_outputs: self.common.special_outputs,
            special_output_keypairs_funder: self.common.special_output_keypairs_funder,
            SKs_self: self.common.SKs_self,
            PKs_other,
            bulletproof_common_nonce: self.bulletproof_common_nonce,
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
    pub bulletproof_common_nonce: bulletproof::CommonNonce,
    pub bulletproof_round_1_self: bulletproof::Round1,
}

impl AliceRedeemer0 {
    /// Run key generation for the redeemer of grin. Specifically for Alice, the
    /// bulletproof common nonce is derived from her X_fund, and the first round
    /// of the multi-party bulletproof protocol is executed.
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        special_output_keypairs_redeemer: SpecialOutputKeyPairsRedeemer,
    ) -> anyhow::Result<Self> {
        // Run key generation for the redeemer of grin
        let common = Redeemer0::new(offer, special_outputs, special_output_keypairs_redeemer);

        // TODO: What follows is duplicated for this and AliceFunder0::new. Could be
        // extracted into grin::Alice0

        // Derive bulletproof common nonce from Alice's X_fund. This signifies a
        // dependency between key generation and multi-party bulletproof generation.
        // Other than generating the bulletproof in a different way it may be
        // cleaner to just separate the bulletproof generation protocol, to
        // perform it right after key generation. The trade-off would be an increase in
        // the number of messages.
        let bulletproof_common_nonce =
            bulletproof::CommonNonce::derive(&common.SKs_self.x.public_key)?;
        // Run round 1 of the bulletproof protocol for Alice
        let bulletproof_round_1_self = bulletproof::Round1::new(&common.SKs_self.x.secret_key)?;

        Ok(Self {
            common,
            bulletproof_common_nonce,
            bulletproof_round_1_self,
        })
    }

    /// Run signing algorithm for redeemer of grin. Also continue with second
    /// round of multi-party bulletproof protocol.
    pub fn transition(
        mut self,
        mut PKs_other: PKs,
        mut y: &mut KeyPair,
        bulletproof_round_1_other: bulletproof::Round1,
    ) -> anyhow::Result<(AliceRedeemer1, RedeemerSigs, bulletproof::Round2)> {
        // Without this check and possible mutation the decrypted Grin redeem signature
        // fails to verify 50% of the time
        normalize_redeem_keys_alice(
            &mut self.common.SKs_self.r_redeem,
            &mut PKs_other.R_redeem,
            &mut y,
        )?;

        // Run Grin redeemer's signing algorithm (also continue with 2nd
        // round of multi-party bulletproof protocol)
        let (state, redeemer_sigs, bulletproof_round_2_self) = self.common.transition(
            self.bulletproof_common_nonce,
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

impl Into<CoinTossingKeys> for AliceFunder0 {
    fn into(self) -> CoinTossingKeys {
        let PKs: PKs = self.common.SKs_self.into();
        vec![PKs.X, PKs.R_fund, PKs.R_redeem, PKs.R_refund]
    }
}

impl Into<CoinTossingKeys> for AliceRedeemer0 {
    fn into(self) -> CoinTossingKeys {
        let PKs: PKs = self.common.SKs_self.into();
        vec![PKs.X, PKs.R_fund, PKs.R_redeem, PKs.R_refund]
    }
}

impl TryInto<PKs> for CoinTossingKeys {
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
