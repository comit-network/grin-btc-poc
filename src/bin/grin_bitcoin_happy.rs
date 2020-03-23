use grin_btc_poc::{alice::Alice0, bitcoin, bob::Bob0, ecdsa, grin, Execute, LookFor};

fn main() -> anyhow::Result<()> {
    // Set up Grin wallets
    let (
        grin_node,
        grin::Wallets {
            funder_wallet: alice_alpha_wallet,
            redeemer_wallet: bob_alpha_wallet,
        },
    ) = grin::Node::start()?;

    let bob_alpha_starting_balance = bob_alpha_wallet.get_balance()?;

    // Set up Bitcoin wallets
    let (
        mut bitcoin_node,
        bitcoin::Wallets {
            funder_wallet: bob_beta_wallet,
            redeemer_wallet: alice_beta_wallet,
        },
    ) = bitcoin::Node::start()?;

    // Base parameters of the swap, including the offer negotiated prior to
    // executing this protocol, and a set of outputs per party to know where the
    // assets come from and go to during the execution phase of the protocol

    let offer_grin = grin::Offer {
        asset: 10_000_000_000,
        fee: 5_000_000,
        expiry: 0,
    };
    let output_keypairs_grin_funder = grin::SpecialOutputKeyPairsFunder::new_random();
    let output_keypairs_grin_redeemer = grin::SpecialOutputKeyPairsRedeemer::new_random();
    let outputs_grin = grin::SpecialOutputs {
        fund_input_key: output_keypairs_grin_funder.fund_input_key.public_key,
        redeem_output_key: output_keypairs_grin_redeemer.redeem_output_key.public_key,
        refund_output_key: output_keypairs_grin_funder.refund_output_key.public_key,
    };

    let offer_bitcoin = bitcoin::Offer {
        asset: 100_000_000,
        fee: 1_000,
        expiry: 0,
    };
    let outputs_bitcoin = bitcoin::WalletOutputs {
        fund_input: bob_beta_wallet.fund_input(),
        fund_change_address: bob_beta_wallet.change_output_address(),
        redeem_address: alice_beta_wallet.redeem_output_address(),
        refund_address: bob_beta_wallet.refund_output_address(),
    };

    // Key generation and signing

    let (alice0, message0) = Alice0::<grin::AliceFunder0, bitcoin::AliceRedeemer0>::new(
        offer_grin.clone(),
        outputs_grin.clone(),
        output_keypairs_grin_funder,
        offer_bitcoin.clone(),
        outputs_bitcoin.clone(),
    )?;

    let (bob0, message1) = Bob0::<grin::BobRedeemer0, bitcoin::BobFunder0>::new(
        offer_grin.clone(),
        outputs_grin,
        output_keypairs_grin_redeemer,
        offer_bitcoin.clone(),
        outputs_bitcoin,
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
    assert!(alice_beta_wallet.verify_payment_to_address(
        alice2.beta_state.redeem_action.transaction.txid(),
        offer_bitcoin.asset
    )?);

    // Verify that bob gets the agreed upon grin
    assert_eq!(
        bob_alpha_wallet.get_balance()?,
        bob_alpha_starting_balance + offer_grin.asset
    );

    // Clean-up

    grin_node.kill();
    bitcoin_node.kill()?;
    Ok(())
}
