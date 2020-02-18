use crate::{
    grin::{
        compute_excess_pk, compute_excess_sk, compute_offset,
        wallet::{build_output, Wallet},
        PKs, SKs,
    },
    keypair::{build_commitment, random_secret_key, KeyPair, PublicKey, SecretKey, SECP},
    schnorr, setup_parameters,
};
use anyhow::Context;
use grin_core::core::{Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use grin_keychain::BlindingFactor;
use grin_wallet_libwallet::{ParticipantData, Slate};
use secp256k1zkp::{aggsig, pedersen::RangeProof, Signature};
use std::convert::TryInto;

pub struct Fund {
    transaction_from_special_input: Transaction,
    special_input_x: (u64, KeyPair),
}

impl Fund {
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey, RangeProof)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        offset: SecretKey,
        special_input_x: (u64, KeyPair),
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_from_special_input: new_transaction(
                inputs,
                outputs,
                excess,
                excess_sig,
                kernel_features,
                offset,
            )
            .context("fund")?,
            special_input_x,
        })
    }
}

pub struct Refund {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

impl Refund {
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey, RangeProof)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        offset: SecretKey,
        special_output_x: KeyPair,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_to_special_output: new_transaction(
                inputs,
                outputs,
                excess,
                excess_sig,
                kernel_features,
                offset,
            )
            .context("refund")?,
            special_output_x: special_output_x.clone(),
        })
    }
}

pub struct EncryptedRedeem {
    incomplete_transaction_to_special_output:
        Box<dyn FnOnce(Signature) -> anyhow::Result<Transaction>>,
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
    ) -> anyhow::Result<Self> {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key)?;

        let X = compute_excess_pk(
            vec![&redeemer_SKs.x.public_key, &funder_PKs.X],
            vec![&init.redeem_output_key],
            Some(&offset),
        )?;

        let R_hat = PublicKey::from_combination(&*SECP, vec![
            &redeemer_SKs.r_redeem.public_key,
            &funder_PKs.R_redeem,
        ])?;
        let R = PublicKey::from_combination(&*SECP, vec![&R_hat, &Y])?;

        let kernel_features = KernelFeatures::Plain { fee: init.fee };

        if !aggsig::verify_single(
            &*SECP,
            &encsig,
            &kernel_features.kernel_sig_msg()?,
            Some(&R),
            &X,
            Some(&X),
            None,
            true,
        ) {
            return Err(anyhow::anyhow!(
                "failed to verify Grin encrypted redeem signature"
            ));
        }

        let incomplete_transaction_to_special_output = {
            let inputs = vec![(
                init.fund_output_amount(),
                PublicKey::from_combination(&*SECP, vec![
                    &redeemer_SKs.x.public_key,
                    &funder_PKs.X,
                ])?,
            )];

            let bulletproof = SECP.bullet_proof(
                init.redeem_output_amount(),
                redeemer_SKs.x.secret_key,
                random_secret_key(),
                random_secret_key(),
                None,
                None,
            );

            let outputs = vec![(
                init.redeem_output_amount(),
                secret_init.redeem_output_key.public_key,
                bulletproof,
            )];

            let offset = compute_offset(&redeemer_SKs.r_redeem.public_key, &funder_PKs.R_redeem)?;
            let excess = compute_excess_pk(
                vec![&redeemer_SKs.x.public_key, &funder_PKs.X],
                vec![&secret_init.redeem_output_key.public_key],
                Some(&offset),
            )?;

            Box::new(move |excess_sig| {
                new_transaction(inputs, outputs, excess, excess_sig, kernel_features, offset)
            })
        };

        Ok(Self {
            incomplete_transaction_to_special_output,
            special_output_x: secret_init.redeem_output_key,
            encsig,
            R_hat,
        })
    }

    pub fn decrypt(self, y: &KeyPair) -> anyhow::Result<Redeem> {
        let excess_sig = schnorr::decsig(&y, &self.encsig, &self.R_hat)?;

        let transaction_to_special_output =
            (self.incomplete_transaction_to_special_output)(excess_sig).context("redeem")?;

        Ok(Redeem {
            transaction_to_special_output,
            special_output_x: self.special_output_x,
        })
    }
}

pub struct Redeem {
    transaction_to_special_output: Transaction,
    special_output_x: KeyPair,
}

fn new_transaction(
    inputs: Vec<(u64, PublicKey)>,
    outputs: Vec<(u64, PublicKey, RangeProof)>,
    excess: PublicKey,
    excess_sig: Signature,
    kernel_features: KernelFeatures,
    offset: SecretKey,
) -> anyhow::Result<Transaction> {
    let inputs = inputs
        .iter()
        .map(|(amount, blind_pk)| {
            let amount_pk = SECP.commit_value(amount.clone())?.to_pubkey(&*SECP)?;
            let commit_pk = PublicKey::from_combination(&*SECP, vec![&amount_pk, &blind_pk])?;

            Ok(Input::new(
                OutputFeatures::Plain,
                build_commitment(&commit_pk),
            ))
        })
        .collect::<Result<Vec<Input>, anyhow::Error>>()?;

    let outputs = outputs
        .iter()
        .map(|(amount, blind_pk, proof)| {
            let amount_pk = SECP.commit_value(amount.clone())?.to_pubkey(&*SECP)?;
            let commit = build_commitment(&PublicKey::from_combination(&*SECP, vec![
                &amount_pk, &blind_pk,
            ])?);

            Ok(Output {
                features: OutputFeatures::Plain,
                commit,
                proof: proof.clone(),
            })
        })
        .collect::<Result<Vec<Output>, anyhow::Error>>()?;

    let excess = build_commitment(&excess);

    let kernel = {
        TxKernel {
            excess,
            excess_sig: excess_sig.clone(),
            features: kernel_features.clone(),
        }
    };

    let offset = BlindingFactor::from_secret_key(offset);
    let transaction = Transaction::new(inputs, outputs, vec![kernel]).with_offset(offset);

    Ok(transaction)
}

pub trait Execute {
    fn execute(self, wallet: &Wallet) -> anyhow::Result<()>;
}

impl Execute for Fund {
    fn execute(self, wallet: &Wallet) -> anyhow::Result<()> {
        // Build invoice to pay to special output
        let (slate, r, blind_excess_keypair) = {
            let mut slate = Slate::blank(2);

            slate.amount = self.special_input_x.0;
            slate.height = wallet.get_chain_tip()?;

            slate.version_info.block_header_version = 3;
            slate.lock_height = 0;

            let special_output = build_output(slate.amount, &self.special_input_x.1.secret_key)?;
            slate.tx = slate.tx.with_output(special_output);

            let r = KeyPair::new_random();

            // Using zero offset for "internal" transaction
            let blind_excess =
                compute_excess_sk(vec![], vec![&self.special_input_x.1.secret_key], None)?;
            let blind_excess_keypair = KeyPair::new(blind_excess);

            slate.participant_data = vec![ParticipantData {
                id: 1,
                public_blind_excess: blind_excess_keypair.public_key,
                public_nonce: r.public_key,
                part_sig: None,
                message: None,
                message_sig: None,
            }];

            (slate, r, blind_excess_keypair)
        };

        let slate = wallet.process_invoice(slate)?;

        // Add special output partial signature and verify aggregate signature
        let transaction_from_funder_wallet_to_special_output = {
            let sender_data = slate
                .participant_data
                .iter()
                .find(|p| p.id == 0)
                .ok_or(anyhow::anyhow!("missing sender data"))?;

            let (sig, excess) = crate::schnorr::sign_2p_1(
                &blind_excess_keypair,
                &r,
                &sender_data.public_blind_excess,
                &sender_data.public_nonce,
                &KernelFeatures::Plain { fee: slate.fee }.kernel_sig_msg()?,
                &sender_data
                    .part_sig
                    .ok_or(anyhow::anyhow!("missing sender partsig"))?
                    .try_into()?,
            )?;

            let mut tx = slate.tx;

            tx.body.kernels[0].excess = build_commitment(&excess);
            tx.body.kernels[0].excess_sig = sig;

            tx.body.kernels[0].verify().map_err(|e| {
                anyhow::anyhow!("failed to verify grin fund transaction kernel: {}", e)
            })?;

            tx
        };

        let aggregate_transaction = grin_core::core::transaction::aggregate(vec![
            transaction_from_funder_wallet_to_special_output.clone(),
            self.transaction_from_special_input.clone(),
        ])
        .map_err(|e| anyhow::anyhow!("failed to aggregate fund transaction: {}", e))?;

        wallet.post_transaction(aggregate_transaction)
    }
}
