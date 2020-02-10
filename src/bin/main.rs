use grin_btc_poc::{
    alice::Alice0,
    bob::Bob0,
    setup_parameters::{Bitcoin, Grin, GrinFunderSecret, GrinRedeemerSecret, SetupParameters},
};
use std::str::FromStr;

fn main() -> Result<(), ()> {
    let grin_funder_secret_init = GrinFunderSecret::new_random();
    let grin_redeemer_secret_init = GrinRedeemerSecret::new_random();

    // TODO: Use proper setup parameters
    let init = SetupParameters {
        alpha: Grin {
            amount: 10_000_000_000,
            fee: 8_000_000,
            expiry: 0,
            fund_input_key: grin_funder_secret_init.fund_input_key.public_key.clone(),
            redeem_output_key: grin_redeemer_secret_init
                .redeem_output_key
                .public_key
                .clone(),
            refund_output_key: grin_funder_secret_init.refund_output_key.public_key.clone(),
        },
        beta: Bitcoin::new(
            100_000_000,
            1_000,
            0,
            vec![(bitcoin::OutPoint::null(), 300_000_000)],
            bitcoin::Address::from_str(
                "bcrt1qc45uezve8vj8nds7ws0da8vfkpanqfxecem3xl7wcs3cdne0358q9zx9qg",
            )
            .unwrap(),
            bitcoin::Address::from_str(
                "bcrt1qs2aderg3whgu0m8uadn6dwxjf7j3wx97kk2qqtrum89pmfcxknhsf89pj0",
            )
            .unwrap(),
            bitcoin::Address::from_str(
                "bcrt1qc45uezve8vj8nds7ws0da8vfkpanqfxecem3xl7wcs3cdne0358q9zx9qg",
            )
            .unwrap(),
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

    alice1.receive(message3)?;

    Ok(())
}
