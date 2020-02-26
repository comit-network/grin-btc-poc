use crate::bitcoin::Transaction;
use bitcoin::{consensus::encode::Encodable, hashes::sha256d, util::psbt::serialize::Deserialize};

pub trait Client {
    fn node_url(&self) -> String;
    fn generate_blocks(&self, n: u32) -> anyhow::Result<()> {
        ureq::post(&self.node_url())
            .send_json(ureq::json!({"jsonrpc": "1.0", "method": "generate", "params": [n] }))
            .into_json()
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("failed to generate blocks: {}", e))
    }

    fn get_rawtransaction(&self, txid: &sha256d::Hash) -> anyhow::Result<Transaction> {
        let res = ureq::post(&Client::node_url(self))
        .send_json(ureq::json!({"jsonrpc": "1.0", "method": "getrawtransaction", "params": [format!("{}", txid), 1] }));

        if res.ok() {
            let json = res.into_json()?;
            let hex_tx = json
                .as_object()
                .expect("response is object")
                .get("result")
                .expect("field exists")
                .get("hex")
                .expect("field exists")
                .as_str()
                .expect("value is string");

            Ok(Transaction::deserialize(&hex::decode(hex_tx)?)?)
        } else {
            Err(anyhow::anyhow!("failed to get raw transaction"))
        }
    }

    fn send_rawtransaction(&self, transaction: &Transaction) -> anyhow::Result<()> {
        let mut raw_tx = vec![];
        transaction
            .consensus_encode(&mut raw_tx)
            .expect("valid transaction");

        let res = ureq::post(&Client::node_url(self))
        .send_json(ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [hex::encode(raw_tx)] }));

        if res.ok() {
            self.generate_blocks(1)?;

            Ok(())
        } else {
            Err(anyhow::anyhow!("failed to send raw transaction"))
        }
    }
}
