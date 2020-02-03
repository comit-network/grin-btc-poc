use grin_btc_poc::{
    alice::{Alice0, Alice1},
    bob::{Bob0, Bob1},
};

fn main() {
    let (alice0, message0) = Alice0::new();

    let (bob0, message1) = Bob0::new(message0);

    let (alice1, message2) = alice0.receive(message1);

    let bob1 = bob0.receive(message2);
}
