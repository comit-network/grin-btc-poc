// NOTE: I don't see this used as a bound anywhere. Consider removing this
// trait.
pub trait LookFor {
    type Event;
    type Extract;

    fn look_for(&self, event: Self::Event) -> anyhow::Result<Self::Extract>;
}
