use crate::{
    keypair::{KeyPair, PublicKey},
    Hash,
};
use blake2::{Blake2b, Digest};

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
    pub r_fund: KeyPair,
    pub r_redeem: KeyPair,
    pub r_refund: KeyPair,
}

impl Into<PKs> for SKs {
    fn into(self) -> PKs {
        PKs {
            X: self.x.public_key,
            R_fund: self.r_fund.public_key,
            R_redeem: self.r_redeem.public_key,
            R_refund: self.r_refund.public_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PKs {
    pub X: PublicKey,
    pub R_fund: PublicKey,
    pub R_redeem: PublicKey,
    pub R_refund: PublicKey,
}

impl Hash for PKs {
    fn hash(&self) -> [u8; 64] {
        let mut hasher = Blake2b::new();

        hasher.input(self.X.0);
        hasher.input(self.R_fund.0);
        hasher.input(self.R_redeem.0);
        hasher.input(self.R_refund.0);

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hasher.result());
        hash
    }
}
