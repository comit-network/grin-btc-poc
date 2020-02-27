use grin_btc_poc::{
    alice::Alice0, bitcoin, bob::Bob0, ecdsa, grin, keypair::random_secret_key, Execute, LookFor,
};

fn main() -> anyhow::Result<()> {
    // Set up Grin wallets
    // TODO: Do it more like Bitcoin
    let alpha_wallets = grin::Wallets::initialize()?;

    let alice_alpha_wallet = &alpha_wallets.0[0];
    alice_alpha_wallet.award_60_grin()?;

    let bob_alpha_wallet = &alpha_wallets.0[1];

    let bob_alpha_starting_balance = bob_alpha_wallet.get_balance()?;

    // Set up Bitcoin wallets
    let (
        mut bitcoin_node,
        bitcoin::Wallets {
            funder_wallet: bob_beta_wallet,
            redeemer_wallet: alice_beta_wallet,
        },
    ) = bitcoin::Node::start()?;

    // Set-up parameters
    let grin_funder_secret_init = grin::FunderSecret::new_random();
    let grin_redeemer_secret_init = grin::RedeemerSecret::new_random();

    // TODO: Use proper setup parameters
    let base_parameters_grin = grin::BaseParameters {
        asset: 10_000_000_000,
        fee: 5_000_000,
        expiry: 0,
        fund_input_key: grin_funder_secret_init.fund_input_key.public_key,
        redeem_output_key: grin_redeemer_secret_init.redeem_output_key.public_key,
        refund_output_key: grin_funder_secret_init.refund_output_key.public_key,
        // TODO: Figure out how to generate the common nonce properly
        bulletproof_common_nonce: random_secret_key(),
    };
    let base_parameters_bitcoin = bitcoin::BaseParameters::new(
        100_000_000,
        1_000,
        0,
        bob_beta_wallet.fund_input(),
        bob_beta_wallet.change_output_address(),
        bob_beta_wallet.refund_output_address(),
        alice_beta_wallet.redeem_output_address(),
    )
    .expect("cannot fail");

    let (alice0, message0) = Alice0::new(
        base_parameters_grin.clone(),
        base_parameters_bitcoin.clone(),
        grin_funder_secret_init,
    )?;

    let (bob0, message1) = Bob0::new(
        base_parameters_grin.clone(),
        base_parameters_bitcoin.clone(),
        grin_redeemer_secret_init,
        message0,
    )?;

    let (alice1, message2) = alice0.receive(message1)?;

    let (bob1, message3) = bob0.receive(message2)?;

    let (alice2, message4) = alice1.receive(message3)?;

    let bob2 = bob1.receive(message4)?;

    // Execution

    alice2
        .alpha_state
        .0
        .fund_action
        .execute(&alice_alpha_wallet)?;

    bob2.beta_state.fund_action.execute(&bob_beta_wallet)?;

    alice2
        .beta_state
        .redeem_action
        .clone()
        .execute(&alice_beta_wallet)?;

    let beta_decrypted_redeem_sig = bob_beta_wallet.look_for(bob2.beta_state.redeem_event)?;
    let y = ecdsa::recover(&beta_decrypted_redeem_sig, &bob2.beta_state.recovery_key)?;
    let alpha_redeem_action = bob2.alpha_state.encrypted_redeem_action.decrypt(&y)?;

    alpha_redeem_action.execute(&bob_alpha_wallet)?;

    // Verify that alice gets the agreed upon bitcoin
    assert!(alice_beta_wallet.verify_payment_to_redeem_output_address(
        alice2.beta_state.redeem_action.transaction.txid(),
        base_parameters_bitcoin.asset
    )?);

    // Verify that bob gets the agreed upon grin
    assert_eq!(
        bob_alpha_wallet.get_balance()?,
        bob_alpha_starting_balance + base_parameters_grin.asset
    );

    grin::Wallets::clean_up();
    bitcoin_node.kill()?;
    Ok(())
}
