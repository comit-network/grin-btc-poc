use crate::{
    grin::{compute_excess_pk, compute_offset, PKs, SKs},
    keypair::{build_commitment, KeyPair, PublicKey, SECP},
    schnorr, setup_parameters,
};
use grin_core::core::{Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use secp256k1zkp::{aggsig, pedersen::RangeProof, Signature};

pub struct Fund {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

impl Fund {
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        special_input_x: KeyPair,
    ) -> Self {
        Self {
            transaction_to_special_output: new_transaction(
                inputs,
                outputs,
                excess,
                excess_sig,
                kernel_features,
            ),
            special_output_x: special_input_x.clone(),
        }
    }
}

pub struct Refund {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

impl Refund {
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        special_output_x: KeyPair,
    ) -> Self {
        Self {
            transaction_to_special_output: new_transaction(
                inputs,
                outputs,
                excess,
                excess_sig,
                kernel_features,
            ),
            special_output_x: special_output_x.clone(),
        }
    }
}

pub struct EncryptedRedeem {
    incomplete_transaction_to_special_output: Box<dyn FnOnce(Signature) -> Transaction>,
    special_output_x: KeyPair,
    encsig: schnorr::EncryptedSignature,
    R_hat: PublicKey,
}

impl EncryptedRedeem {
    pub fn new(
        init: setup_parameters::Grin,
        secret_init: setup_parameters::GrinRedeemerSecret,
        redeemer_SKs: SKs,
        funder_PKs: PKs,
        Y: PublicKey,
        encsig: schnorr::EncryptedSignature,
    ) -> Result<Self, ()> {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key);

        let X = compute_excess_pk(
            vec![&redeemer_SKs.x.public_key, &funder_PKs.X],
            vec![&init.redeem_output_key],
            Some(&offset),
        )
        .unwrap();

        let R_hat = PublicKey::from_combination(&*SECP, vec![
            &redeemer_SKs.r_redeem.public_key,
            &funder_PKs.R_redeem,
        ])
        .unwrap();
        let R = PublicKey::from_combination(&*SECP, vec![&R_hat, &Y]).unwrap();

        let kernel_features = KernelFeatures::Plain { fee: init.fee };

        if !aggsig::verify_single(
            &*SECP,
            &encsig,
            &kernel_features.kernel_sig_msg().unwrap(),
            Some(&R),
            &X,
            Some(&X),
            None,
            true,
        ) {
            return Err(());
        }

        let incomplete_transaction_to_special_output = {
            let inputs = vec![(
                init.fund_output_amount(),
                PublicKey::from_combination(&*SECP, vec![
                    &redeemer_SKs.x.public_key,
                    &funder_PKs.X,
                ])
                .unwrap(),
            )];

            let outputs = vec![(
                init.redeem_output_amount(),
                secret_init.redeem_output_key.public_key,
            )];

            let offset = compute_offset(&redeemer_SKs.r_redeem.public_key, &funder_PKs.R_redeem);
            let excess = compute_excess_pk(
                vec![&redeemer_SKs.x.public_key, &funder_PKs.X],
                vec![&secret_init.redeem_output_key.public_key],
                Some(&offset),
            )
            .unwrap();

            Box::new(move |excess_sig| {
                new_transaction(inputs, outputs, excess, excess_sig, kernel_features)
            })
        };

        Ok(Self {
            incomplete_transaction_to_special_output,
            special_output_x: secret_init.redeem_output_key,
            encsig,
            R_hat,
        })
    }

    pub fn decrypt(self, y: &KeyPair) -> Redeem {
        let excess_sig = schnorr::decsig(&y, &self.encsig, &self.R_hat);

        let transaction_to_special_output =
            (self.incomplete_transaction_to_special_output)(excess_sig);

        Redeem {
            transaction_to_special_output,
            special_output_x: self.special_output_x,
        }
    }
}

pub struct Redeem {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

fn new_transaction(
    inputs: Vec<(u64, PublicKey)>,
    outputs: Vec<(u64, PublicKey)>,
    excess: PublicKey,
    excess_sig: Signature,
    kernel_features: KernelFeatures,
) -> Transaction {
    let inputs = inputs
        .iter()
        .map(|(amount, blind_pk)| {
            let amount_pk = SECP
                .commit_value(amount.clone())
                .unwrap()
                .to_pubkey(&*SECP)
                .unwrap();
            let commit_pk =
                PublicKey::from_combination(&*SECP, vec![&amount_pk, &blind_pk]).unwrap();

            Input::new(OutputFeatures::Plain, build_commitment(&commit_pk))
        })
        .collect();

    let outputs = outputs
        .iter()
        .map(|(amount, blind_pk)| {
            let amount_pk = SECP
                .commit_value(amount.clone())
                .unwrap()
                .to_pubkey(&*SECP)
                .unwrap();
            let commit = build_commitment(
                &PublicKey::from_combination(&*SECP, vec![&amount_pk, &blind_pk]).unwrap(),
            );

            // TODO: Use a valid rangeproof
            let proof = RangeProof::zero();
            Output {
                features: OutputFeatures::Plain,
                commit,
                proof,
            }
        })
        .collect();

    let kernel = {
        TxKernel {
            excess: build_commitment(&excess),
            excess_sig: excess_sig.clone(),
            features: kernel_features.clone(),
        }
    };

    Transaction::new(inputs, outputs, vec![kernel])
}
