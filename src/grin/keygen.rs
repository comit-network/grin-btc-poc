use crate::{grin::SKs, KeyPair};

/// Generate half-private key (or half-blinding factor) for one half of the fund
/// output (x or x_fund) and half-nonces for fund, redeem and refund signatures.
///
/// To be called by both Alice and Bob, which will later need to collaborate
/// using their keys to produce valid joint signatures.
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
