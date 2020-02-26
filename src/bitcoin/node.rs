use crate::{
    bitcoin::{
        wallet::{find_output, FunderWallet, Output, RedeemerWallet},
        Address, Client, OutPoint,
    },
    keypair::KeyPair,
};
use bitcoin_hashes::sha256d;
use std::{
    process::{Child, Command, Stdio},
    str::FromStr,
};

pub struct Node {
    url: String,
    process: Child,
}

impl Node {
    pub fn start() -> anyhow::Result<(Node, Wallets)> {
        let process = Command::new("bitcoind")
            .args(&[
                "-regtest",
                "-server",
                "-rpcuser=user",
                "-rpcpassword=password",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        std::thread::sleep(std::time::Duration::from_millis(2000));

        let url = "http://user:password@localhost:18443";
        let node = Node {
            process,
            url: url.into(),
        };

        node.generate_blocks(100)?;

        let fund_input = node.mint(3)?;

        let funder_wallet = FunderWallet::new(url.into(), fund_input)?;
        let redeemer_wallet = RedeemerWallet::new(url.into());

        Ok((node, Wallets {
            funder_wallet,
            redeemer_wallet,
        }))
    }

    pub fn kill(&mut self) -> anyhow::Result<()> {
        self.process.kill().map_err(|e| {
            anyhow::anyhow!(
                "could not kill bitcoind process {}: {}",
                self.process.id(),
                e
            )
        })
    }

    pub fn mint(&self, amount: u8) -> anyhow::Result<Output> {
        let keypair = KeyPair::new_random();

        let address = keypair.to_bitcoin_address();
        let txid = self.send_to_address(&address, amount)?;
        let transaction = self.get_rawtransaction(&txid)?;
        let (vout, txout) = find_output(&transaction, &address).ok_or_else(|| {
            anyhow::anyhow!(
                "failed to find output for address {} in transaction {:?}",
                &address,
                &transaction
            )
        })?;

        Ok(Output::new(keypair, OutPoint { txid, vout }, txout.clone()))
    }

    fn send_to_address(&self, address: &Address, amount: u8) -> anyhow::Result<sha256d::Hash> {
        let res = ureq::post(&self.url)
            .send_json(ureq::json!({"jsonrpc": "1.0", "method": "sendtoaddress", "params": [format!("{}", address), amount] }));

        if res.ok() {
            let json = &res.into_json()?;
            let string = json["result"].as_str().expect("value is string");
            Ok(sha256d::Hash::from_str(&string).unwrap())
        } else {
            Err(anyhow::anyhow!("failed to send to address"))
        }
    }
}

impl Client for Node {
    fn node_url(&self) -> String {
        self.url.clone()
    }
}

pub struct Wallets {
    pub funder_wallet: FunderWallet,
    pub redeemer_wallet: RedeemerWallet,
}
