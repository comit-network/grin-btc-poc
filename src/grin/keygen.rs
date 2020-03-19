use crate::{grin::SKs, KeyPair};

pub fn keygen() -> SKs {
    let x = KeyPair::new_random();

    let r_fund = KeyPair::new_random();
    let r_redeem = KeyPair::new_random();
    let r_refund = KeyPair::new_random();

    SKs {
        x,
        r_fund,
        r_redeem,
        r_refund,
    }
}
