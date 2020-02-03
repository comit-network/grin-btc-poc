use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin,
};

pub struct Message0(pub Commitment);

pub struct Message1 {
    pub PKs_grin: grin::PKs,
    pub PKs_bitcoin: bitcoin::PKs,
}

pub struct Message2 {
    pub opening: Opening,
}
