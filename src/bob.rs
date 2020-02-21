use crate::{
    bitcoin,
    commit::Commitment,
    grin, keypair,
    keypair::KeyPair,
    messages::{Message0, Message1, Message2, Message3, Message4},
    setup_parameters::{self, SetupParameters},
};

pub struct Bob0 {
    init: SetupParameters,
    secret_grin_init: setup_parameters::GrinRedeemerSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    bulletproof_round_1_alice: grin::bulletproof::Round1,
    bulletproof_round_1_bob: grin::bulletproof::Round1,
    alice_commitment: Commitment,
}

impl Bob0 {
    pub fn new(
        init: SetupParameters,
        secret_grin_init: setup_parameters::GrinRedeemerSecret,
        message0: Message0,
    ) -> (Bob0, Message1) {
        let (SKs_alpha, bulletproof_round_1_bob) = grin::keygen();
        let SKs_beta = bitcoin::SKs::keygen();

        let state = Bob0 {
            init,
            secret_grin_init,
            SKs_alpha: SKs_alpha.clone(),
            SKs_beta: SKs_beta.clone(),
            bulletproof_round_1_alice: message0.bulletproof_round_1_alice,
            bulletproof_round_1_bob: bulletproof_round_1_bob.clone(),
            alice_commitment: message0.commitment,
        };

        let message = Message1 {
            PKs_alpha: SKs_alpha.public(),
            PKs_beta: SKs_beta.public(),
            bulletproof_round_1_bob,
        };

        (state, message)
    }

    pub fn receive(
        self,
        Message2 {
            opening,
            beta_redeemer_sigs: alice_beta_refund_signature,
        }: Message2,
    ) -> Result<(Bob1, Message3), ()> {
        let (alice_PKs_alpha, alice_PKs_beta, Y) = opening.open(self.alice_commitment)?;

        let (beta_actions, beta_redeem_encsig) = bitcoin::sign::funder(
            &self.init.beta,
            &self.SKs_beta,
            &alice_PKs_beta,
            &Y,
            &alice_beta_refund_signature,
        )?;

        let beta_recovery_key = crate::ecdsa::reckey(&Y, &beta_redeem_encsig);

        // TODO: handle the fact that grin signing produces both signatures and
        // "partial" bulletproofs
        let alpha_redeemer_sigs = grin::sign::redeemer(
            &self.init.alpha,
            &self.secret_grin_init,
            &self.SKs_alpha,
            &alice_PKs_alpha,
            &Y,
            &self.bulletproof_round_1_bob,
            &self.bulletproof_round_1_alice,
        );

        let state = Bob1 {
            init: self.init,
            secret_grin_init: self.secret_grin_init,
            SKs_alpha: self.SKs_alpha,
            SKs_beta: self.SKs_beta,
            alice_PKs_alpha,
            alice_PKs_beta,
            Y,
            beta_fund_action: beta_actions.fund,
            beta_refund_action: beta_actions.refund,
            beta_recovery_key,
        };

        let message = Message3 {
            beta_redeem_encsig,
            alpha_redeemer_sigs: alpha_redeemer_sigs.0,
            bulletproof_round_2_bob: alpha_redeemer_sigs.1,
        };

        Ok((state, message))
    }
}

pub struct Bob1 {
    init: SetupParameters,
    secret_grin_init: setup_parameters::GrinRedeemerSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_PKs_alpha: grin::PKs,
    alice_PKs_beta: bitcoin::PKs,
    Y: keypair::PublicKey,
    beta_fund_action: bitcoin::action::Fund,
    beta_refund_action: bitcoin::action::Refund,
    beta_recovery_key: crate::ecdsa::RecoveryKey,
}

impl Bob1 {
    pub fn receive(self, message: Message4) -> Result<Bob2, ()> {
        let alpha_encrypted_redeem_action = grin::action::EncryptedRedeem::new(
            self.init.alpha,
            self.secret_grin_init,
            self.SKs_alpha,
            self.alice_PKs_alpha,
            self.Y,
            message.alpha_redeem_encsig,
        )?;

        Ok(Bob2 {
            beta_fund_action: self.beta_fund_action,
            beta_refund_action: self.beta_refund_action,
            alpha_encrypted_redeem_action,
            beta_recovery_key: self.beta_recovery_key,
        })
    }
}

pub struct Bob2 {
    pub beta_fund_action: bitcoin::action::Fund,
    pub beta_refund_action: bitcoin::action::Refund,
    pub alpha_encrypted_redeem_action: grin::action::EncryptedRedeem,
    pub beta_recovery_key: crate::ecdsa::RecoveryKey,
}

impl Bob2 {
    pub fn receive_beta_redeem_tx(self, transaction: bitcoin::Transaction) -> Bob3 {
        use keypair::SECP;
        use secp256k1zkp::Signature;

        let y = transaction.input[0]
            .witness
            .iter()
            .find_map(|witness| {
                if witness.len() == 0 {
                    return None;
                }
                let sig_bytes = &witness[..witness.len() - 1]; // remove last byte which is SIGHASH flag
                match Signature::from_der(&*SECP, sig_bytes) {
                    // TODO: instead of just blindly trying everything, find the signature corresponding to Bob's key
                    Ok(sig) => {
                        match crate::ecdsa::recover(
                            &crate::ecdsa::Signature::from(sig),
                            &self.beta_recovery_key,
                        ) {
                            Ok(y) => Some(KeyPair::new(y)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            })
            .expect("Alice can't steal the money without revealing y");

        Bob3 {
            alpha_redeem_action: self.alpha_encrypted_redeem_action.decrypt(&y),
        }
    }
}

#[derive(Debug)]
pub struct Bob3 {
    pub alpha_redeem_action: grin::action::Redeem,
}
