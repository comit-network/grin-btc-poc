use crate::PublicKey;
use blake2::{Blake2b, Digest};

pub struct Commitment([u8; 64]);

pub struct Opening {
    PKs_alpha: Vec<PublicKey>,
    PKs_beta: Vec<PublicKey>,
    Y: PublicKey,
}

pub type CoinTossingKeys = Vec<PublicKey>;

impl Commitment {
    pub fn commit(
        PKs_alpha: CoinTossingKeys,
        PKs_beta: CoinTossingKeys,
        Y: &PublicKey,
    ) -> Commitment {
        let mut hasher = Blake2b::new();

        for pk in PKs_alpha.iter() {
            hasher.input(pk.0);
        }

        for pk in PKs_beta.iter() {
            hasher.input(pk.0);
        }

        hasher.input(Y.0);

        let mut commitment = [0u8; 64];
        commitment.copy_from_slice(&hasher.result());

        Commitment(commitment)
    }
}

impl Opening {
    pub fn new(PKs_alpha: CoinTossingKeys, PKs_beta: CoinTossingKeys, Y: PublicKey) -> Self {
        Opening {
            PKs_alpha,
            PKs_beta,
            Y,
        }
    }

    pub fn open(
        self,
        commitment: Commitment,
    ) -> anyhow::Result<(CoinTossingKeys, CoinTossingKeys, PublicKey)> {
        let self_commitment =
            Commitment::commit(self.PKs_alpha.clone(), self.PKs_beta.clone(), &self.Y);

        if commitment.0[..] == self_commitment.0[..] {
            Ok((self.PKs_alpha, self.PKs_beta, self.Y))
        } else {
            Err(anyhow::anyhow!("Opening does not match commitment"))
        }
    }
}
