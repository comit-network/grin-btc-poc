use crate::{
    grin::{
        compute_excess_pk, compute_excess_sk, compute_offset,
        wallet::{build_input, build_output},
        Offer, PKs, SKs, SpecialOutputKeyPairsRedeemer, SpecialOutputs, Wallet,
    },
    keypair::{build_commitment, random_secret_key, KeyPair, PublicKey, SecretKey, SECP},
    schnorr, Execute,
};
use anyhow::Context;
use grin_core::core::{Input, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use grin_keychain::BlindingFactor;
use grin_wallet_libwallet::{ParticipantData, Slate};
use secp256k1zkp::{aggsig, pedersen::RangeProof, Signature};
use std::convert::TryInto;

pub struct Fund {
    transaction_from_special_input: Transaction,
    special_input: (u64, KeyPair),
}

impl Fund {
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey, RangeProof)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        offset: SecretKey,
        special_input: (u64, KeyPair),
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
            special_input,
        })
    }
}

pub struct Refund {
    transaction_to_special_output: Transaction,
    special_output: (u64, KeyPair),
    wallet_transaction_fee: u64,
}

impl Refund {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inputs: Vec<(u64, PublicKey)>,
        outputs: Vec<(u64, PublicKey, RangeProof)>,
        excess: PublicKey,
        excess_sig: Signature,
        kernel_features: KernelFeatures,
        offset: SecretKey,
        special_output: (u64, KeyPair),
        wallet_transaction_fee: u64,
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
            special_output,
            wallet_transaction_fee,
        })
    }
}

pub struct EncryptedRedeem {
    incomplete_transaction_to_special_output:
        Box<dyn FnOnce(Signature) -> anyhow::Result<Transaction>>,
    special_output: (u64, KeyPair),
    wallet_transaction_fee: u64,
    encsig: schnorr::EncryptedSignature,
    R_hat: PublicKey,
}

impl EncryptedRedeem {
    pub fn new(
        offer: Offer,
        special_outputs: SpecialOutputs,
        special_output_keypairs_redeemer: SpecialOutputKeyPairsRedeemer,
        redeemer_SKs: SKs,
        funder_PKs: PKs,
        Y: PublicKey,
        encsig: schnorr::EncryptedSignature,
    ) -> anyhow::Result<Self> {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key)?;

        let excess_pk = compute_excess_pk(
            vec![&redeemer_SKs.x.public_key, &funder_PKs.X],
            vec![&special_outputs.redeem_output_key],
            Some(&offset),
        )?;

        let R_hat = PublicKey::from_combination(&*SECP, vec![
            &redeemer_SKs.r_redeem.public_key,
            &funder_PKs.R_redeem,
        ])?;
        let R = PublicKey::from_combination(&*SECP, vec![&R_hat, &Y])?;

        let kernel_features = KernelFeatures::Plain { fee: 0 };

        if !aggsig::verify_single(
            &*SECP,
            &encsig,
            &kernel_features.kernel_sig_msg()?,
            Some(&R),
            &excess_pk,
            Some(&excess_pk),
            None,
            true,
        ) {
            return Err(anyhow::anyhow!(
                "failed to verify Grin encrypted redeem signature"
            ));
        }

        let incomplete_transaction_to_special_output = {
            let inputs = vec![(
                offer.fund_output_amount(),
                PublicKey::from_combination(&*SECP, vec![
                    &redeemer_SKs.x.public_key,
                    &funder_PKs.X,
                ])?,
            )];

            let bulletproof = SECP.bullet_proof(
                offer.fund_output_amount(),
                special_output_keypairs_redeemer
                    .redeem_output_key
                    .secret_key
                    .clone(),
                random_secret_key(),
                random_secret_key(),
                None,
                None,
            );

            let outputs = vec![(
                offer.fund_output_amount(),
                special_output_keypairs_redeemer
                    .redeem_output_key
                    .public_key,
                bulletproof,
            )];

            Box::new(move |excess_sig| {
                if !aggsig::verify_single(
                    &*SECP,
                    &excess_sig,
                    &kernel_features.kernel_sig_msg()?,
                    Some(&R),
                    &excess_pk,
                    Some(&excess_pk),
                    None,
                    false,
                ) {
                    return Err(anyhow::anyhow!(
                        "failed to verify Grin decrypted redeem signature"
                    ));
                }

                new_transaction(
                    inputs,
                    outputs,
                    excess_pk,
                    excess_sig,
                    kernel_features,
                    offset,
                )
            })
        };

        Ok(Self {
            incomplete_transaction_to_special_output,
            special_output: (
                offer.fund_output_amount(),
                special_output_keypairs_redeemer.redeem_output_key,
            ),
            wallet_transaction_fee: offer.fee,
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
            special_output: self.special_output,
            wallet_transaction_fee: self.wallet_transaction_fee,
        })
    }
}

#[derive(Debug)]
pub struct Redeem {
    transaction_to_special_output: Transaction,
    special_output: (u64, KeyPair),
    wallet_transaction_fee: u64,
}

fn new_transaction(
    inputs: Vec<(u64, PublicKey)>,
    outputs: Vec<(u64, PublicKey, RangeProof)>,
    excess_pk: PublicKey,
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
                proof: *proof,
            })
        })
        .collect::<Result<Vec<Output>, anyhow::Error>>()?;

    let excess = build_commitment(&excess_pk);

    let kernel = {
        TxKernel {
            excess,
            excess_sig,
            features: kernel_features,
        }
    };

    let offset = BlindingFactor::from_secret_key(offset);
    let transaction = Transaction::new(inputs, outputs, vec![kernel]).with_offset(offset);

    Ok(transaction)
}

impl Execute for Fund {
    type Wallet = Wallet;
    type Return = u64;

    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        // Build invoice to pay to special output
        let (slate, r, blind_excess_keypair) = {
            let mut slate = Slate::blank(2);

            slate.amount = self.special_input.0;
            slate.height = wallet.get_chain_tip()?;

            slate.version_info.block_header_version = 3;
            slate.lock_height = 0;

            let special_output = build_output(slate.amount, &self.special_input.1.secret_key)?;
            slate.tx = slate.tx.with_output(special_output);

            let r = KeyPair::new_random();

            // Using zero offset for "internal" transaction
            let blind_excess =
                compute_excess_sk(vec![], vec![&self.special_input.1.secret_key], None)?;
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
                .ok_or_else(|| anyhow::anyhow!("missing sender data"))?;

            let (sig, excess) = crate::schnorr::sign_2p_1(
                &blind_excess_keypair,
                &r,
                &sender_data.public_blind_excess,
                &sender_data.public_nonce,
                &KernelFeatures::Plain { fee: slate.fee }.kernel_sig_msg()?,
                &sender_data
                    .part_sig
                    .ok_or_else(|| anyhow::anyhow!("missing sender partsig"))?
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
            transaction_from_funder_wallet_to_special_output,
            self.transaction_from_special_input,
        ])
        .map_err(|e| anyhow::anyhow!("failed to aggregate fund transaction: {}", e))?;

        let fee = aggregate_transaction.fee();
        wallet.post_transaction(aggregate_transaction)?;

        Ok(fee)
    }
}

impl Execute for Redeem {
    type Wallet = Wallet;
    type Return = u64;
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        aggregate_with_spending_transaction(
            self.transaction_to_special_output,
            self.special_output,
            self.wallet_transaction_fee,
            wallet,
        )
    }
}

impl Execute for Refund {
    type Wallet = Wallet;
    type Return = u64;
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        aggregate_with_spending_transaction(
            self.transaction_to_special_output,
            self.special_output,
            self.wallet_transaction_fee,
            wallet,
        )
    }
}

pub fn aggregate_with_spending_transaction(
    transaction_to_special_output: Transaction,
    special_output: (u64, KeyPair),
    wallet_transaction_fee: u64,
    wallet: &Wallet,
) -> anyhow::Result<u64> {
    let mut slate = wallet.issue_invoice(special_output.0 - wallet_transaction_fee)?;

    slate.fee = wallet_transaction_fee;
    slate.update_kernel();

    let special_input = build_input(special_output.0, &special_output.1.secret_key)?;
    slate.tx = slate.tx.with_input(special_input);

    let r = KeyPair::new_random();

    let blind_excess = compute_excess_sk(vec![&special_output.1.secret_key], vec![], None)?;
    let blind_excess_keypair = KeyPair::new(blind_excess);

    slate.participant_data.push(ParticipantData {
        id: 0,
        public_blind_excess: blind_excess_keypair.public_key,
        public_nonce: r.public_key,
        part_sig: None,
        message: None,
        message_sig: None,
    });

    let receiver_data = slate
        .participant_data
        .iter()
        .find(|p| p.id == 1)
        .ok_or_else(|| anyhow::anyhow!("missing sender data"))?;

    // The aggregate transaction will contain another kernel which will be height
    // locked according to the expiry defined in the offer. Therefore, there is no
    // need to height lock the kernel corresponding to the other transaction
    // involved
    let partial_sig = schnorr::sign_2p_0(
        &blind_excess_keypair,
        &r,
        &receiver_data.public_blind_excess,
        &receiver_data.public_nonce,
        &KernelFeatures::Plain { fee: slate.fee }.kernel_sig_msg()?,
    )?;

    for p in slate.participant_data.iter_mut() {
        if p.id == 0 {
            p.part_sig = Some(partial_sig.to_signature(&r.public_key)?);
        }
    }

    let transaction_from_special_input_to_wallet = wallet.finalize_invoice(slate)?;

    let aggregate_transaction = grin_core::core::transaction::aggregate(vec![
        transaction_to_special_output,
        transaction_from_special_input_to_wallet,
    ])
    .map_err(|e| anyhow::anyhow!("failed to aggregate refund transaction: {}", e))?;

    let fee = aggregate_transaction.fee();
    wallet.post_transaction(aggregate_transaction)?;

    Ok(fee)
}
