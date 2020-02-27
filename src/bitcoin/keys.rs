use crate::{
    keypair::{KeyPair, PublicKey},
    Hash,
};
use blake2::{Blake2b, Digest};

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
}

impl Into<PKs> for SKs {
    fn into(self) -> PKs {
        PKs {
            X: self.x.public_key,
        }
    }
}

pub struct PKs {
    pub X: PublicKey,
}

impl Hash for PKs {
    fn hash(&self) -> [u8; 64] {
        let mut hasher = Blake2b::new();

        hasher.input(self.X.0);

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hasher.result());
        hash
    }
}
