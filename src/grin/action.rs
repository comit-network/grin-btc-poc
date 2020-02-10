use crate::keypair::{build_commitment, KeyPair, PublicKey, SECP};
use grin_core::core::{Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use secp256k1zkp::{pedersen::RangeProof, Signature};

pub struct Fund {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

pub struct Refund {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

pub struct Redeem {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

impl Fund {
    pub fn new(
        inputs: &Vec<(u64, PublicKey)>,
        outputs: &Vec<(u64, PublicKey)>,
        excess: &PublicKey,
        excess_sig: &Signature,
        kernel_features: &KernelFeatures,
        special_input_x: &KeyPair,
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

impl Refund {
    pub fn new(
        inputs: &Vec<(u64, PublicKey)>,
        outputs: &Vec<(u64, PublicKey)>,
        excess: &PublicKey,
        excess_sig: &Signature,
        kernel_features: &KernelFeatures,
        special_output_x: &KeyPair,
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

impl Redeem {
    pub fn new(
        inputs: &Vec<(u64, PublicKey)>,
        outputs: &Vec<(u64, PublicKey)>,
        excess: &PublicKey,
        excess_sig: &Signature,
        kernel_features: &KernelFeatures,
        special_output_x: &KeyPair,
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

fn new_transaction(
    inputs: &Vec<(u64, PublicKey)>,
    outputs: &Vec<(u64, PublicKey)>,
    excess: &PublicKey,
    excess_sig: &Signature,
    kernel_features: &KernelFeatures,
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
