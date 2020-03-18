use grin_btc_poc::{
    alice::Alice0, bitcoin, bob::Bob0, grin, keypair::random_secret_key, schnorr, Execute, LookFor,
};

fn main() -> anyhow::Result<()> {
    // Set up Bitcoin wallets
    let (
        mut bitcoin_node,
        bitcoin::Wallets {
            funder_wallet: alice_alpha_wallet,
            redeemer_wallet: bob_alpha_wallet,
        },
    ) = bitcoin::Node::start()?;

    // Set up Grin wallets
    let beta_wallets = grin::Wallets::initialize()?;

    let alice_beta_wallet = &beta_wallets.0[0];

    let bob_beta_wallet = &beta_wallets.0[1];
    bob_beta_wallet.award_60_grin()?;

    let alice_beta_starting_balance = alice_beta_wallet.get_balance()?;

    // Set-up parameters
    let grin_funder_secret_init = grin::FunderSecret::new_random();
    let grin_redeemer_secret_init = grin::RedeemerSecret::new_random();

    let offer_grin = grin::Offer {
        asset: 10_000_000_000,
        fee: 5_000_000,
        expiry: 0,
    };
    let outputs_grin = grin::SpecialOutputs {
        fund_input_key: grin_funder_secret_init.fund_input_key.public_key,
        redeem_output_key: grin_redeemer_secret_init.redeem_output_key.public_key,
        refund_output_key: grin_funder_secret_init.refund_output_key.public_key,
        // TODO: Figure out how to generate the common nonce properly
        bulletproof_common_nonce: random_secret_key(),
    };

    let offer_bitcoin = bitcoin::Offer {
        asset: 100_000_000,
        fee: 1_000,
        expiry: 0,
    };
    let outputs_bitcoin = bitcoin::WalletOutputs {
        fund_input: alice_alpha_wallet.fund_input(),
        fund_change_address: alice_alpha_wallet.change_output_address(),
        redeem_address: bob_alpha_wallet.redeem_output_address(),
        refund_address: alice_alpha_wallet.refund_output_address(),
    };

    let (alice0, message0) = Alice0::<bitcoin::AliceFunder0, grin::AliceRedeemer0>::new(
        offer_bitcoin.clone(),
        outputs_bitcoin.clone(),
        offer_grin.clone(),
        outputs_grin.clone(),
        grin_redeemer_secret_init,
    )?;

    let (bob0, message1) = Bob0::<bitcoin::BobRedeemer0, grin::BobFunder0>::new(
        offer_bitcoin.clone(),
        outputs_bitcoin,
        offer_grin.clone(),
        outputs_grin,
        grin_funder_secret_init,
        message0,
    )?;

    let (alice1, message2) = alice0.receive(message1)?;

    let (bob1, message3) = bob0.receive(message2)?;

    let (alice2, message4) = alice1.receive(message3)?;

    let bob2 = bob1.receive(message4)?;

    alice2
        .alpha_state
        .fund_action
        .execute(&alice_alpha_wallet)?;

    bob2.beta_state.fund_action.execute(&bob_beta_wallet)?;

    alice2
        .beta_state
        .redeem_action
        .execute(&alice_beta_wallet)?;

    let beta_decrypted_redeem_sig = bob_beta_wallet.look_for(bob2.beta_state.redeem_event)?;
    let y = schnorr::recover(&beta_decrypted_redeem_sig, &bob2.beta_state.recovery_key)?;
    let alpha_redeem_action = bob2.alpha_state.encrypted_redeem_action.decrypt(&y);
    let alpha_redeem_txid = alpha_redeem_action.transaction.txid();

    alpha_redeem_action.execute(&bob_alpha_wallet)?;

    // Verify that alice gets the agreed upon grin
    assert_eq!(
        alice_beta_wallet.get_balance()?,
        alice_beta_starting_balance + offer_grin.asset
    );

    // Verify that bob gets the agreed upon bitcoin
    assert!(bob_alpha_wallet
        .verify_payment_to_redeem_output_address(alpha_redeem_txid, offer_bitcoin.asset)?);

    grin::Wallets::clean_up();
    bitcoin_node.kill()?;
    Ok(())
}
