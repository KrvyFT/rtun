pub enum Protocol {
    ICMP = 1,
    UDP = 17,
    Unknown = 255,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::ICMP,
            17 => Protocol::UDP,
            _ => Protocol::Unknown,
        }
    }
}
