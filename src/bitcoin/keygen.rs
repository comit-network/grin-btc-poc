use crate::{bitcoin::SKs, KeyPair};

/// Generate a keypair for one of the public keys for Bitcoin's fund OPCMS.
///
/// To be called by both Alice and Bob, which will later need to collaborate
/// using their keys to produce valid signatures based on this.
pub fn keygen() -> SKs {
    let x = KeyPair::new_random();

    SKs { x }
}
