use crate::{
    bitcoin::{event, Address, Client, OutPoint, Script, Signature, Transaction, TxOut},
    keypair::{verify_ecdsa, KeyPair, PublicKey, SECP},
    LookFor,
};
use bitcoin::{
    hashes::{hash160, Hash},
    util::bip143::SighashComponents,
    SigHashType,
};
use bitcoin_hashes::sha256d;
use secp256k1zkp::Message;

pub struct FunderWallet {
    url: String,
    fund_input: Output,
    change_output_keypair: KeyPair,
    refund_output_keypair: KeyPair,
}

impl FunderWallet {
    pub fn new(url: String, fund_input: Output) -> anyhow::Result<Self> {
        Ok(Self {
            url,
            fund_input,
            change_output_keypair: KeyPair::new_random(),
            refund_output_keypair: KeyPair::new_random(),
        })
    }

    pub fn change_output_address(&self) -> Address {
        self.change_output_keypair.to_bitcoin_address()
    }

    pub fn refund_output_address(&self) -> Address {
        self.refund_output_keypair.to_bitcoin_address()
    }

    pub fn fund_input(&self) -> Output {
        self.fund_input.clone()
    }

    pub fn sign_input(&self, transaction: Transaction) -> anyhow::Result<Transaction> {
        let mut completed_tx = transaction;
        let sighash_components = SighashComponents::new(&completed_tx);

        for ref mut input in &mut completed_tx.input {
            let wallet_input = self.fund_input();

            let owned_output = if input.previous_output == wallet_input.outpoint {
                &wallet_input
            } else {
                return Err(anyhow::anyhow!(
                    "transaction input {:?} not owned by wallet",
                    input
                ));
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

pub struct RedeemerWallet {
    url: String,
    redeem_output_keypair: KeyPair,
}

impl RedeemerWallet {
    pub fn new(url: String) -> Self {
        Self {
            url,
            redeem_output_keypair: KeyPair::new_random(),
        }
    }

    pub fn redeem_output_address(&self) -> Address {
        self.redeem_output_keypair.to_bitcoin_address()
    }

    pub fn verify_payment_to_redeem_output_address(
        &self,
        txid: sha256d::Hash,
        amount: u64,
    ) -> anyhow::Result<bool> {
        let transaction = self.get_rawtransaction(&txid)?;

        Ok(transaction.output[0].value == amount)
    }
}

impl Client for FunderWallet {
    fn node_url(&self) -> String {
        self.url.clone()
    }
}

impl Client for RedeemerWallet {
    fn node_url(&self) -> String {
        self.url.clone()
    }
}

impl LookFor for FunderWallet {
    type Event = event::Redeem;
    type Extract = crate::ecdsa::Signature;

    fn look_for(&self, event: Self::Event) -> anyhow::Result<Self::Extract> {
        let transaction = self.get_rawtransaction(&event.txid)?;

        // the redeem transaction contains 1 input
        transaction.input[0]
            .witness
            .iter()
            .find_map(|witness| {
                if witness.len() == 0 {
                    return None;
                }

                // remove last byte which is SIGHASH flag
                let sig_bytes = &witness[..witness.len() - 1];

                match Signature::from_der(&*SECP, sig_bytes) {
                    Ok(sig) if verify_ecdsa(&event.message_hash, &sig, &event.funder_pk) => {
                        Some(sig.into())
                    }
                    _ => None,
                }
            })
            .ok_or_else(|| {
                anyhow::anyhow!("failed to find signature corresponding to redeemer's public key")
            })
    }
}

#[derive(Clone, Debug)]
pub struct Output {
    pub keypair: KeyPair,
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

impl Output {
    pub fn new(keypair: KeyPair, outpoint: OutPoint, txout: TxOut) -> Self {
        Self {
            keypair,
            outpoint,
            txout,
        }
    }

    pub fn address(&self) -> Address {
        self.keypair.to_bitcoin_address()
    }
}

pub fn find_output<'a>(
    transaction: &'a Transaction,
    to_address: &Address,
) -> Option<(u32, &'a TxOut)> {
    let to_address_script_pubkey = to_address.script_pubkey();

    transaction
        .output
        .iter()
        .enumerate()
        .map(|(index, txout)| {
            // Casting a usize to u32 can lead to truncation on 64bit platforms
            // However, bitcoin limits the number of inputs to u32 anyway, so this
            // is not a problem for us.
            #[allow(clippy::cast_possible_truncation)]
            (index as u32, txout)
        })
        .find(|(_, txout)| txout.script_pubkey == to_address_script_pubkey)
}

pub fn signature_into_witness(sig: Signature) -> Vec<u8> {
    let mut serialized_signature = sig.serialize_der(&*SECP).to_vec();
    serialized_signature.push(SigHashType::All as u8);
    serialized_signature
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
