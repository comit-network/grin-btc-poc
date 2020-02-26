pub trait LookFor {
    type Event;
    type Extract;

    fn look_for(&self, event: Self::Event) -> anyhow::Result<Self::Extract>;
}
