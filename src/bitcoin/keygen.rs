use crate::{bitcoin::SKs, KeyPair};

pub fn keygen() -> SKs {
    let x = KeyPair::new_random();

    SKs { x }
}
