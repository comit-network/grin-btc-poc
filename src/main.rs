use bitcoin::OutPoint;
use grin_btc_poc::{
    alice::Alice0,
    bob::Bob0,
    grin::{self, action::Execute},
    keypair::random_secret_key,
    setup_parameters::{Bitcoin, Grin, GrinFunderSecret, GrinRedeemerSecret, SetupParameters},
    LookFor,
};
use std::{convert::TryInto, str::FromStr};

fn main() -> anyhow::Result<()> {
    let grin_funder_secret_init = GrinFunderSecret::new_random();
    let grin_redeemer_secret_init = GrinRedeemerSecret::new_random();

    // TODO: Use proper setup parameters
    let init = SetupParameters {
        alpha: Grin {
            asset: 10_000_000_000,
            fee: 5_000_000,
            expiry: 0,
            fund_input_key: grin_funder_secret_init.fund_input_key.public_key.clone(),
            redeem_output_key: grin_redeemer_secret_init
                .redeem_output_key
                .public_key
                .clone(),
            refund_output_key: grin_funder_secret_init.refund_output_key.public_key.clone(),
            // TODO: Figure out how to generate the common nonce properly
            bulletproof_common_nonce: random_secret_key(),
        },
        beta: Bitcoin::new(
            100_000_000,
            1_000,
            0,
            vec![(OutPoint::null(), 300_000_000)],
            bitcoin::Address::from_str(
                "bcrt1qc45uezve8vj8nds7ws0da8vfkpanqfxecem3xl7wcs3cdne0358q9zx9qg",
            )?,
            bitcoin::Address::from_str(
                "bcrt1qs2aderg3whgu0m8uadn6dwxjf7j3wx97kk2qqtrum89pmfcxknhsf89pj0",
            )?,
            bitcoin::Address::from_str(
                "bcrt1qc45uezve8vj8nds7ws0da8vfkpanqfxecem3xl7wcs3cdne0358q9zx9qg",
            )?,
        )
        .expect("cannot fail"),
    };

    let (alice0, message0) = Alice0::new(init.clone(), grin_funder_secret_init)?;

    let (bob0, message1) = Bob0::new(init.clone(), grin_redeemer_secret_init, message0)?;

    let (alice1, message2) = alice0.receive(message1)?;
    // TODO: Remove once we involve Bitcoin transactions
    let y = alice1.y.clone();

    let (bob1, message3) = bob0.receive(message2)?;

    let (alice2, message4) = alice1.receive(message3)?;

    let bob2 = bob1.receive(message4)?;

    // TODO: Consider moving wallets into Alice and Bob so that we can keep the code
    // in main.rs at a higher level

    // Set up wallets
    let grin_wallets = grin::Wallets::initialize()?;

    let alice_grin_wallet = &grin_wallets.0[0];
    alice_grin_wallet.award_60_grin()?;

    let bob_grin_wallet = &grin_wallets.0[1];

    // Alice funds Grin
    alice2.alpha_fund_action.execute(&alice_grin_wallet)?;

    let grin_starting_balance_bob = bob_grin_wallet.get_balance()?;

    // Bob redeems Grin (ignoring Bitcoin in the meantime)
    let grin_encsig = bob2.alpha_encrypted_redeem_action.encsig.clone();

    let alpha_redeem_action = bob2.alpha_encrypted_redeem_action.decrypt(&y)?;
    alpha_redeem_action.execute(&bob_grin_wallet)?;

    // Verify that bob gets the agreed upon grin
    assert_eq!(
        bob_grin_wallet.get_balance()?,
        grin_starting_balance_bob + init.alpha.asset
    );

    // TODO: Remove all this. Just testing that you can extract the signature from
    // Bob's redeem transaction
    let grin_decrypted_redeem_sig = bob_grin_wallet.look_for(bob2.beta_redeem_event)?;
    let y_tag =
        grin_btc_poc::schnorr::recover(&grin_decrypted_redeem_sig, &grin_encsig.try_into()?)?;

    assert_eq!(y_tag, y.secret_key);

    grin::Wallets::clean_up();
    Ok(())
}
