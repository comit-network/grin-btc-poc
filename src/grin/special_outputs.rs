use crate::{KeyPair, PublicKey};

/// Special outputs allow the signing phase to occur without knowledge of the
/// actual wallet outputs of either party. They can be generated locally and
/// will be erased via cut-through even before a transaction involving them is
/// published to the blockchain.

#[derive(Clone)]
pub struct SpecialOutputs {
    pub fund_input_key: PublicKey,
    pub redeem_output_key: PublicKey,
    pub refund_output_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct SpecialOutputKeyPairsFunder {
    pub fund_input_key: KeyPair,
    pub refund_output_key: KeyPair,
}

impl SpecialOutputKeyPairsFunder {
    pub fn new_random() -> Self {
        Self {
            fund_input_key: KeyPair::new_random(),
            refund_output_key: KeyPair::new_random(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpecialOutputKeyPairsRedeemer {
    pub redeem_output_key: KeyPair,
}

impl SpecialOutputKeyPairsRedeemer {
    pub fn new_random() -> Self {
        Self {
            redeem_output_key: KeyPair::new_random(),
        }
    }
}
