use crate::{
    bitcoin::{
        rpc::OwnedOutput,
        transaction::{fund_transaction, redeem_transaction},
        Hash, PKs, SKs, SigHashType, SighashComponents, Signature, Transaction,
    },
    ecdsa,
    keypair::{KeyPair, PublicKey, SECP},
    setup_parameters,
};
use bitcoin::{hashes::hash160, Script};
use secp256k1zkp::Message;

pub struct Fund {
    pub transaction: Transaction,
}

impl Fund {
    pub fn sign_inputs(&self, owned_outputs: Vec<OwnedOutput>) -> Result<Transaction, ()> {
        let mut completed_tx = self.transaction.clone();
        let sighash_components = SighashComponents::new(&completed_tx);
        for ref mut input in &mut completed_tx.input {
            let owned_output = match owned_outputs
                .iter()
                .find(|candidate| candidate.outpoint == input.previous_output)
            {
                Some(matched) => matched,
                None => return Err(()),
            };

            let fund_digest = {
                let digest = sighash_components.sighash_all(
                    &input,
                    &generate_prev_script_p2wpkh(&owned_output.keypair.public_key),
                    owned_output.txout.value,
                );

                Message::from_slice(&digest.into_inner()).expect("always correct length")
            };

            let signature_element = {
                let signature = owned_output.keypair.sign_ecdsa(&fund_digest);
                signature_into_witness(signature)
            };

            input.witness = vec![
                signature_element,
                owned_output
                    .keypair
                    .public_key
                    .serialize_vec(&*SECP, true)
                    .to_vec(),
            ]
        }

        Ok(completed_tx)
    }
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
        init: &setup_parameters::Bitcoin,
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
        let funder_sig = dbg!(ecdsa::decsig(&y, &self.funder_encsig)).into();

        let mut completed_transaction = self.transaction;
        dbg!(crate::ecdsa::reckey(&y.public_key, &self.funder_encsig));
        dbg!(funder_sig);
        let funder_witness = signature_into_witness(funder_sig);
        let redeemer_witness = signature_into_witness(self.redeemer_sig);

        completed_transaction.input[0].witness = vec![
            vec![], // You have to put some extra shit on the stack because OP_CHECKMULTISIG is buggy
            redeemer_witness,
            funder_witness,
            self.fund_output_script.to_bytes(),
        ];

        Redeem {
            transaction: completed_transaction,
        }
    }
}

pub struct Redeem {
    pub transaction: Transaction,
}

fn generate_prev_script_p2wpkh(public_key: &PublicKey) -> Script {
    let public_key_hash =
        hash160::Hash::hash(public_key.serialize_vec(&*SECP, true).to_vec().as_ref());

    let mut prev_script = vec![0x76, 0xa9, 0x14];

    prev_script.append(&mut public_key_hash[..].to_vec());
    prev_script.push(0x88);
    prev_script.push(0xac);

    Script::from(prev_script)
}

pub fn signature_into_witness(sig: Signature) -> Vec<u8> {
    let mut serialized_signature = sig.serialize_der(&*SECP).to_vec();
    serialized_signature.push(SigHashType::All as u8);
    serialized_signature
}
