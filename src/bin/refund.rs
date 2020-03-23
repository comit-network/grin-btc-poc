use grin_btc_poc::{alice::Alice0, bitcoin, bob::Bob0, grin, Execute};

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
    let (
        grin_node,
        grin::Wallets {
            funder_wallet: bob_beta_wallet,
            ..
        },
    ) = grin::Node::start()?;

    let bob_beta_starting_balance = bob_beta_wallet.get_balance()?;

    // Base parameters of the swap, including the offer negotiated prior to
    // executing this protocol, and a set of outputs per party to know where the
    // assets come from and go to during the execution phase of the protocol

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

    // Key generation and signing

    let (alice0, message0) = Alice0::<bitcoin::AliceFunder0, grin::AliceRedeemer0>::new(
        offer_bitcoin.clone(),
        outputs_bitcoin.clone(),
        offer_grin.clone(),
        outputs_grin.clone(),
        output_keypairs_grin_redeemer,
    )?;

    let (bob0, message1) = Bob0::<bitcoin::BobRedeemer0, grin::BobFunder0>::new(
        offer_bitcoin.clone(),
        outputs_bitcoin,
        offer_grin,
        outputs_grin,
        output_keypairs_grin_funder,
        message0,
    )?;

    let (alice1, message2) = alice0.receive(message1)?;

    let (bob1, message3) = bob0.receive(message2)?;

    let (alice2, message4) = alice1.receive(message3)?;

    let bob2 = bob1.receive(message4)?;

    // Execution

    alice2
        .alpha_state
        .fund_action
        .execute(&alice_alpha_wallet)?;

    let fund_fee = bob2.beta_state.fund_action.execute(&bob_beta_wallet)?;

    alice2
        .alpha_state
        .refund_action
        .clone()
        .execute(&alice_alpha_wallet)?;

    let refund_fee = bob2.beta_state.refund_action.execute(&bob_beta_wallet)?;

    // Verify that alice gets her bitcoin back
    assert!(alice_alpha_wallet.verify_payment_to_address(
        alice2.alpha_state.refund_action.transaction.txid(),
        offer_bitcoin.asset
    )?);

    // Verify that bob has the same amount of grin as before (minus fees)
    assert_eq!(
        bob_beta_wallet.get_balance()?,
        bob_beta_starting_balance - fund_fee - refund_fee
    );

    // Clean-up

    bitcoin_node.kill()?;
    grin_node.kill();
    Ok(())
}
