use std::net::Ipv4Addr;

use crate::protocol::protocol::Checksum;

pub struct UdpPacket<'a> {
    raw_data: &'a [u8],
}

impl<'a> Checksum for UdpPacket<'a> {}

impl<'a> UdpPacket<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self { raw_data: slice }
    }

    pub fn get_source_port(&self) -> u16 {
        ((self.raw_data[0] as u16) << 8) | (self.raw_data[1] as u16)
    }

    pub fn get_destination_port(&self) -> u16 {
        ((self.raw_data[2] as u16) << 8) | (self.raw_data[3] as u16)
    }

    pub fn get_length(&self) -> u16 {
        ((self.raw_data[4] as u16) << 8) | (self.raw_data[5] as u16)
    }

    pub fn get_checksum(&self) -> u16 {
        ((self.raw_data[6] as u16) << 8) | (self.raw_data[7] as u16)
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw_data[8..]
    }

    pub fn build_udp_packet(
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;

        // 1. 性能优化：一次性分配足够内存，避免多次 extend_from_slice 引起的扩容
        let mut packet = Vec::with_capacity(20 + payload.len());

        // 2. 写入 20 字节伪首部 (仅用于计算校验和)
        packet.extend_from_slice(&src_addr.octets());
        packet.extend_from_slice(&dst_addr.octets());
        packet.push(0);
        packet.push(17); // UDP Protocol Number
        packet.extend_from_slice(&udp_len.to_be_bytes());

        // 3. 写入 8 字节真实的 UDP 头 (偏移量 12 处)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0u8, 0u8]); // 校验和占位

        // 4. 写入载荷
        packet.extend_from_slice(payload);

        // 5. 计算校验和 (伪首部 + UDP头 + 载荷)
        let mut csum = Self::calc_checksum(&packet);

        // 🔥 核心修补 (RFC 768): UDP 校验和若计算为 0x0000，必须发送为 0xFFFF
        // 否则接收端会误认为未启用校验和
        if csum == 0 {
            csum = 0xffff;
        }

        // 6. 将合法的校验和填回真实的 UDP 头中 (偏移 18 和 19 字节处)
        packet[18..20].copy_from_slice(&csum.to_be_bytes());
        // 7. 零开销移除伪首部，返还真实的 UDP 包
        packet.drain(0..12);
        packet
    }
}
