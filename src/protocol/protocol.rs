pub enum Protocol {
    Icmp = 1,
    Udp = 17,
    Unknown = 255,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            17 => Protocol::Udp,
            _ => Protocol::Unknown,
        }
    }
}

pub trait Checksummable {
    fn calc_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;

        while i < data.len() - 1 {
            let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
            sum += word;
            i += 2;
        }

        if i < data.len() {
            let word = (data[i] as u32) << 8;
            sum += word;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }
}
