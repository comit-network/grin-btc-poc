use rand::Rng;

pub mod keypair;

pub use keypair::{KeyPair, PublicKey};

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
}

impl SKs {
    pub fn keygen() -> SKs {
        let x = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        SKs { x }
    }

    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key.clone(),
        }
    }
}

pub struct PKs {
    pub X: PublicKey,
}
