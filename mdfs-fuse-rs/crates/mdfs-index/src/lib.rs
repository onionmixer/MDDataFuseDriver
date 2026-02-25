#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case9Tag {
    Tag45,
    Tag48,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case9Record {
    pub tag: Case9Tag,
    pub out2: u8,
    pub out3: u8,
    pub out4: u8,
    pub out5: u8,
    pub out7: u8,
    pub out8: u8,
}
