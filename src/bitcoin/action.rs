use crate::{
    bitcoin::{
        self,
        transaction::{fund_transaction, redeem_transaction},
        wallet::{signature_into_witness, FunderWallet, RedeemerWallet},
        Client, PKs, SKs, Signature, Transaction,
    },
    ecdsa,
    keypair::KeyPair,
    Execute,
};
use ::bitcoin::{hashes::Hash, util::bip143::SighashComponents, Script};
use secp256k1zkp::Message;

pub struct Fund {
    pub transaction: Transaction,
}

pub struct Refund {
    pub transaction: Transaction,
    pub redeemer_sig: Signature,
    pub funder_sig: Signature,
}

impl Refund {
    pub fn new(transaction: Transaction, redeemer_sig: Signature, funder_sig: Signature) -> Self {
        Self {
            transaction,
            redeemer_sig,
            funder_sig,
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
        init: &bitcoin::BaseParameters,
        redeemer_SKs: &SKs,
        funder_PKs: &PKs,
        funder_encsig: ecdsa::EncryptedSignature,
    ) -> Self {
        let (fund_transaction, fund_output_script) =
            fund_transaction(&init, &redeemer_SKs.x.public_key, &funder_PKs.X);

        let redeem_transaction = redeem_transaction(&init, fund_transaction.txid());

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

        Self {
            transaction: redeem_transaction,
            redeemer_sig,
            funder_encsig,
            fund_output_script,
        }
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
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<()> {
        let transaction = wallet.sign_input(self.transaction)?;

        wallet.send_rawtransaction(&transaction)
    }
}

impl Execute for Redeem {
    type Wallet = RedeemerWallet;
    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<()> {
        wallet.send_rawtransaction(&self.transaction)
    }
}
