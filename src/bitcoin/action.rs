use crate::{
    bitcoin::{
        transaction::{fund_transaction, redeem_transaction},
        wallet::{signature_into_witness, FunderWallet, RedeemerWallet},
        wallet_outputs::WalletOutputs,
        Client, Offer, PKs, SKs, Signature, Transaction,
    },
    ecdsa,
    keypair::KeyPair,
    Execute,
};
use ::bitcoin::{hashes::Hash, util::bip143::SighashComponents, Script};
use anyhow::Context;
use secp256k1zkp::Message;

#[derive(Clone)]
pub struct Fund {
    pub transaction: Transaction,
}

#[derive(Clone)]
pub struct Refund {
    pub transaction: Transaction,
}

impl Refund {
    pub fn new(
        transaction: Transaction,
        redeemer_sig: Signature,
        funder_sig: Signature,
        fund_output_script: Script,
    ) -> Self {
        let mut completed_transaction = transaction;
        let funder_witness = signature_into_witness(funder_sig);
        let redeemer_witness = signature_into_witness(redeemer_sig);

        completed_transaction.input[0].witness = vec![
            vec![], /* You have to put some extra shit on the stack because OP_CHECKMULTISIG is
                     * buggy */
            redeemer_witness,
            funder_witness,
            fund_output_script.to_bytes(),
        ];

        Refund {
            transaction: completed_transaction,
        }
    }
}

pub struct EncryptedRedeem {
    pub transaction: Transaction,
    pub redeemer_sig: Signature,
    pub funder_encsig: ecdsa::EncryptedSignature,
    pub fund_output_script: Script,
}

impl EncryptedRedeem {
    pub fn new(
        offer: &Offer,
        wallet_outputs: &WalletOutputs,
        redeemer_SKs: &SKs,
        funder_PKs: &PKs,
        funder_encsig: ecdsa::EncryptedSignature,
    ) -> anyhow::Result<Self> {
        let (fund_transaction, fund_output_script) = fund_transaction(
            &offer,
            &wallet_outputs,
            &redeemer_SKs.x.public_key,
            &funder_PKs.X,
        )?;

        let redeem_transaction =
            redeem_transaction(&offer, &wallet_outputs, fund_transaction.txid());

        let redeemer_sig = {
            let redeem_digest = SighashComponents::new(&redeem_transaction).sighash_all(
                &redeem_transaction.input[0],
                &fund_output_script,
                fund_transaction.output[0].value,
            );
            let redeem_digest = Message::from_slice(&redeem_digest.into_inner())
                .expect("should not fail because it is a hash");

            redeemer_SKs.x.sign_ecdsa(&redeem_digest)
        };

        Ok(Self {
            transaction: redeem_transaction,
            redeemer_sig,
            funder_encsig,
            fund_output_script,
        })
    }

    pub fn decrypt(self, y: &KeyPair) -> Redeem {
        let funder_sig = ecdsa::decsig(&y, &self.funder_encsig).into();

        let mut completed_transaction = self.transaction;
        let funder_witness = signature_into_witness(funder_sig);
        let redeemer_witness = signature_into_witness(self.redeemer_sig);

        completed_transaction.input[0].witness = vec![
            vec![], /* You have to put some extra shit on the stack because OP_CHECKMULTISIG is
                     * buggy */
            redeemer_witness,
            funder_witness,
            self.fund_output_script.to_bytes(),
        ];

        Redeem {
            transaction: completed_transaction,
        }
    }
}

#[derive(Clone)]
pub struct Redeem {
    pub transaction: Transaction,
}

impl Execute for Fund {
    type Wallet = FunderWallet;
    type Return = ();
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        let transaction = wallet.sign_fund_input(self.transaction)?;

        wallet.send_rawtransaction(&transaction).context("fund")
    }
}

impl Execute for Redeem {
    type Wallet = RedeemerWallet;
    type Return = ();
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        wallet
            .send_rawtransaction(&self.transaction)
            .context("redeem")
    }
}

impl Execute for Refund {
    type Wallet = FunderWallet;
    type Return = ();
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return> {
        wallet
            .send_rawtransaction(&self.transaction)
            .context("refund")
    }
}
