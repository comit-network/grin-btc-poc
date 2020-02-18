use grin_btc_poc::{
    alice::Alice0,
    bob::Bob0,
    keypair::{KeyPair,random_secret_key},
    setup_parameters::{Bitcoin, Grin, GrinFunderSecret, GrinRedeemerSecret, SetupParameters},
    bitcoin::util::{send_rawtransaction, new_owned_output},
};
use std::str::FromStr;

fn main() -> Result<(), ()> {
    let bob_input = new_owned_output(3).expect("funding bob initial input");
    dbg!(&bob_input);
    let bob_change = KeyPair::new_random();
    let alice_redeem_keypair = KeyPair::new_random();
    let bob_refund_keypair = KeyPair::new_random();

    let grin_funder_secret_init = GrinFunderSecret::new_random();
    let grin_redeemer_secret_init = GrinRedeemerSecret::new_random();

    // TODO: Use proper setup parameters
    let init = SetupParameters {
        alpha: Grin {
            asset: 10_000_000_000,
            fee: 8_000_000,
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
            vec![(bob_input.outpoint , bob_input.txout.value)],
            bob_change.to_bitcoin_address(),
            bob_refund_keypair.to_bitcoin_address(),
            alice_redeem_keypair.to_bitcoin_address(),
        )
        .expect("cannot fail"),
    };

    let (alice0, message0) = Alice0::new(init.clone(), grin_funder_secret_init);

    let (bob0, message1) = Bob0::new(init, grin_redeemer_secret_init, message0);

    dbg!("alice0 receive");

    let (alice1, message2) = alice0.receive(message1).expect("message1");

    dbg!("bob0 receive");

    let (bob1, message3) = bob0.receive(message2)?;

    dbg!("alice1 receive");

    let (alice2, message4) = alice1.receive(message3)?;

    dbg!("bob1 receive");

    let bob2 = bob1.receive(message4)?;

    let funding_tx = &bob2.beta_fund_action.sign_inputs(vec![bob_input]).expect("funding tx signing");

    send_rawtransaction(&funding_tx).expect("funding tx broadcast");
    Ok(())
}
