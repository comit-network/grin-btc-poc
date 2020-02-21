use crate::bitcoin::{Address, OutPoint, Transaction};
use crate::keypair::KeyPair;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::consensus::encode::Encodable;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin_hashes::sha256d;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct OwnedOutput {
    pub keypair: KeyPair,
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

pub fn generate_blocks(n: u32) {
    let _json_res = ureq::post("http://user:password@localhost:18443").send_json(
        ureq::json!({"jsonrpc": "1.0", "id":"grin-btc-poc", "method": "generate", "params": [n] }),
    ).into_json().expect("block generation should work");
}

pub fn new_owned_output(btc: u8) -> Result<OwnedOutput, ()> {
    let keypair = KeyPair::new_random();
    let address = keypair.to_bitcoin_address();
    let txid = send_to_address(&address, btc)?;
    let transaction = get_rawtransaction(&txid)?;
    let (vout, txout) = find_output(&transaction, &address).ok_or(())?;
    return Ok(OwnedOutput {
        keypair,
        outpoint: OutPoint { txid, vout },
        txout: txout.clone(),
    });
}

pub fn send_to_address(address: &Address, btc: u8) -> Result<sha256d::Hash, ()> {
    let res = ureq::post("http://user:password@localhost:18443")
        .send_json(ureq::json!({"jsonrpc": "1.0", "id":"grin-btc-poc", "method": "sendtoaddress", "params": [format!("{}", address), btc] }));

    if res.ok() {
        let json = &res.into_json().unwrap();
        let string = json["result"].as_str().unwrap();
        Ok(sha256d::Hash::from_str(&string).unwrap())
    } else {
        Err(())
    }
}

pub fn get_rawtransaction(txid: &sha256d::Hash) -> Result<Transaction, ()> {
    let res = ureq::post("http://user:password@localhost:18443")
        .send_json(ureq::json!({"jsonrpc": "1.0", "id":"grin-btc-poc", "method": "getrawtransaction", "params": [format!("{}", txid), 1] }));

    if res.ok() {
        let json = res.into_json().unwrap();
        let hex_tx = json
            .as_object()
            .unwrap()
            .get("result")
            .unwrap()
            .get("hex")
            .unwrap()
            .as_str()
            .unwrap();

        Ok(Transaction::deserialize(&hex::decode(hex_tx).unwrap()).unwrap())
    } else {
        Err(())
    }
}

fn find_output<'a>(transaction: &'a Transaction, to_address: &Address) -> Option<(u32, &'a TxOut)> {
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

pub fn send_rawtransaction(transaction: &Transaction) -> Result<(), ()> {
    let mut raw_tx = vec![];
    transaction
        .consensus_encode(&mut raw_tx)
        .expect("valid transaction");

    let res = ureq::post("http://user:password@localhost:18443")
        .send_json(ureq::json!({"jsonrpc": "1.0", "id":"grin-btc-poc", "method": "sendrawtransaction", "params": [hex::encode(raw_tx)] }));

    if res.ok() {
        Ok(())
    } else {
        dbg!(res.into_json());
        Err(())
    }
}
