use super::tcp_flags::TcpFlags;

pub struct TcpPacket<'a> {
    raw: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.raw[0..2].try_into().unwrap())
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes(self.raw[2..4].try_into().unwrap())
    }

    pub fn seq_number(&self) -> u32 {
        u32::from_be_bytes(self.raw[4..8].try_into().unwrap())
    }

    pub fn ack_number(&self) -> u32 {
        u32::from_be_bytes(self.raw[8..12].try_into().unwrap())
    }

    pub fn header_len(&self) -> u8 {
        let data_offset = self.raw[12] >> 4;
        data_offset * 4
    }

    pub fn flags(&self) -> TcpFlags {
        TcpFlags::parse(self.raw[13])
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.header_len() as usize;
        &self.raw[len..]
    }
}
