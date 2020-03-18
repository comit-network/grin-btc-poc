use crate::{
    grin::{event, Signature},
    keypair::{random_secret_key, SECP},
    look_for::LookFor,
};
use grin_chain::Chain;
use grin_core::core::{Input, Output, OutputFeatures, Transaction, TxKernel};
use grin_util::ZeroingString;
use grin_wallet_impls::{
    test_framework::{award_blocks_to_wallet, wallet_info, LocalWalletClient, WalletProxy},
    DefaultLCProvider, DefaultWalletImpl,
};
use grin_wallet_libwallet::{InitTxArgs, IssueInvoiceTxArgs, NodeClient, Slate, WalletInst};
use grin_wallet_util::{grin_keychain::ExtKeychain, grin_util::Mutex};
use secp256k1zkp::{pedersen::Commitment, SecretKey};
use std::{sync::Arc, thread};

lazy_static::lazy_static! {
    static ref CHAIN_DIR: &'static str = "target/test_output/";
}

pub struct Wallets(pub Vec<Wallet>);

impl Wallets {
    pub fn initialize() -> anyhow::Result<Self> {
        let _ = std::fs::remove_dir_all(&*CHAIN_DIR);
        let mut wallet_proxy: WalletProxy<
            DefaultLCProvider<LocalWalletClient, ExtKeychain>,
            LocalWalletClient,
            ExtKeychain,
        > = WalletProxy::new(&*CHAIN_DIR);

        let mut wallets = Vec::new();
        for id in vec!["alice", "bob"].iter() {
            let node_client = LocalWalletClient::new(id, wallet_proxy.tx.clone());
            let mut wallet = Box::new(
                DefaultWalletImpl::<LocalWalletClient>::new(node_client.clone())
                    .map_err(|e| anyhow::anyhow!("failed to instantiate Grin wallet: {}", e))?,
            )
                as Box<
                    dyn WalletInst<
                        DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
                        LocalWalletClient,
                        ExtKeychain,
                    >,
                >;
            let lc_provider = wallet.lc_provider().map_err(|e| {
                anyhow::anyhow!("failed to get stored instance of lifecycle provider: {}", e)
            })?;
            lc_provider
                .set_top_level_directory(&format!("{}/{}", "target/test_output/", id))
                .map_err(|e| anyhow::anyhow!("failed to set top level directory: {}", e))?;
            lc_provider
                .create_wallet(None, None, 32, ZeroingString::from(""), false)
                .map_err(|e| anyhow::anyhow!("failed to create Grin wallet: {}", e))?;
            let mask = lc_provider
                .open_wallet(None, ZeroingString::from(""), false, false)
                .map_err(|e| anyhow::anyhow!("failed to open Grin wallet: {}", e))?;

            let wallet = Arc::new(Mutex::new(wallet));
            wallet_proxy.add_wallet(
                &id,
                node_client.get_send_instance(),
                wallet.clone(),
                mask.clone(),
            );

            let chain = wallet_proxy.chain.clone();

            let wallet = Wallet {
                inner: wallet,
                node_client,
                mask,
                chain,
            };

            wallets.push(wallet)
        }

        thread::spawn({
            move || {
                if let Err(e) = wallet_proxy.run() {
                    panic!("Wallet Proxy error: {}", e);
                }
            }
        });

        Ok(Self(wallets))
    }

    pub fn clean_up() {
        let _ = std::fs::remove_dir_all(&*CHAIN_DIR);
    }
}

#[allow(clippy::type_complexity)]
pub struct Wallet {
    inner: Arc<
        Mutex<
            Box<
                dyn WalletInst<
                        'static,
                        DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
                        LocalWalletClient,
                        ExtKeychain,
                    > + 'static,
            >,
        >,
    >,
    node_client: LocalWalletClient,
    mask: Option<SecretKey>,
    chain: Arc<Chain>,
}

impl Wallet {
    pub fn get_chain_tip(&self) -> anyhow::Result<u64> {
        self.node_client
            .get_chain_tip()
            .map(|(tip, _)| tip)
            .map_err(|e| anyhow::anyhow!("could not get Grin chain tip: {}", e))
    }

    pub fn process_invoice(&self, slate: Slate) -> anyhow::Result<Slate> {
        let mut processed_slate = Slate::blank(2);
        grin_wallet_controller::controller::owner_single_use(
            self.inner.clone(),
            self.mask.as_ref(),
            |api, m| {
                let args = InitTxArgs {
                    src_acct_name: None,
                    amount: slate.amount,
                    minimum_confirmations: 1,
                    max_outputs: 500,
                    num_change_outputs: 1,
                    selection_strategy_is_use_all: true,
                    ..Default::default()
                };
                processed_slate = api.process_invoice_tx(m, &slate, args)?;
                api.tx_lock_outputs(m, &processed_slate, 0)?;
                Ok(())
            },
        )
        .map(|_| processed_slate)
        .map_err(|e| anyhow::anyhow!("could not process invoice: {}", e))
    }
    pub fn post_transaction(&self, transaction: Transaction) -> anyhow::Result<()> {
        grin_wallet_controller::controller::owner_single_use(
            self.inner.clone(),
            self.mask.as_ref(),
            |api, m| {
                api.post_tx(m, &transaction, false)?;
                Ok(())
            },
        )
        .map_err(|e| anyhow::anyhow!("could not post transaction: {}", e))
    }

    // 1 block reward (60 grin) is spendable after 4 blocks have been mined
    pub fn award_60_grin(&self) -> anyhow::Result<()> {
        award_blocks_to_wallet(
            self.chain.as_ref(),
            self.inner.clone(),
            self.mask.as_ref(),
            4,
            false,
        )
        .map_err(|e| anyhow::anyhow!("could not award grin to wallet: {}", e))
    }

    pub fn issue_invoice(&self, amount: u64) -> anyhow::Result<Slate> {
        let mut invoice_slate = Slate::blank(2);
        grin_wallet_controller::controller::owner_single_use(
            self.inner.clone(),
            self.mask.as_ref(),
            |api, m| {
                let args = IssueInvoiceTxArgs {
                    amount,
                    ..Default::default()
                };
                invoice_slate = api.issue_invoice_tx(m, args)?;
                Ok(())
            },
        )
        .map(|_| invoice_slate)
        .map_err(|e| anyhow::anyhow!("could not issue invoice: {}", e))
    }

    pub fn finalize_invoice(&self, slate: Slate) -> anyhow::Result<Transaction> {
        let mut finalized_slate = Slate::blank(2);
        grin_wallet_controller::controller::foreign_single_use(
            self.inner.clone(),
            self.mask.clone(),
            |api| {
                finalized_slate = api.finalize_invoice_tx(&slate)?;
                Ok(())
            },
        )
        .map(|_| finalized_slate.tx)
        .map_err(|e| anyhow::anyhow!("could not finalize invoice: {}", e))
    }

    pub fn get_balance(&self) -> anyhow::Result<u64> {
        wallet_info(self.inner.clone(), self.mask.as_ref())
            .map(|info| info.amount_currently_spendable)
            .map_err(|e| anyhow::anyhow!("failed to access wallet balance: {}", e))
    }

    pub fn find_kernel(&self, excess: &Commitment) -> anyhow::Result<TxKernel> {
        self.chain
            .get_kernel_height(&excess, None, None)
            .map_err(|e| anyhow::anyhow!("failed to search for kernel: {}", e))?
            .map(|(kernel, ..)| kernel)
            .ok_or_else(|| anyhow::anyhow!("could not find kernel for commitment: {:?}", excess))
    }
}

impl LookFor for Wallet {
    type Event = event::Redeem;
    type Extract = Signature;

    fn look_for(&self, event: Self::Event) -> anyhow::Result<Self::Extract> {
        let kernel = self.find_kernel(&event.excess)?;

        Ok(kernel.excess_sig)
    }
}

pub fn build_input(amount: u64, secret_key: &SecretKey) -> anyhow::Result<Input> {
    let commit = SECP
        .commit(amount, secret_key.clone())
        .map_err(|e| anyhow::anyhow!("failed to build Pedersen commitment: {}", e))?;

    Ok(Input {
        features: OutputFeatures::Plain,
        commit,
    })
}

pub fn build_output(amount: u64, secret_key: &SecretKey) -> anyhow::Result<Output> {
    let commit = SECP
        .commit(amount, secret_key.clone())
        .map_err(|e| anyhow::anyhow!("failed to build Pedersen commitment: {}", e))?;

    // These are just used for random number generation inside bullet proof C
    let rewind_nonce = random_secret_key();
    let private_nonce = random_secret_key();

    let proof = SECP.bullet_proof(
        amount,
        secret_key.clone(),
        rewind_nonce,
        private_nonce,
        None,
        None,
    );

    Ok(Output {
        features: OutputFeatures::Plain,
        commit,
        proof,
    })
}
