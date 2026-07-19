use std::net::Ipv4Addr;

use crate::protocol::protocol::{Checksum, Protocol};

#[derive(Debug)]
pub struct IPV4Packet<'a> {
    raw_data: &'a [u8],
}

impl<'a> Checksum for IPV4Packet<'a> {}

impl<'a> IPV4Packet<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        IPV4Packet { raw_data: slice }
    }

    pub fn build_ipv4_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: Protocol,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = (20 + payload.len()) as u16;

        let mut packet = vec![0u8; total_len as usize];

        // 版本号 (4) 和头部长度 (5, 代表 5 个 32位字 = 20字节)
        packet[0] = 0x45;

        // 总长度 (Total Length)，大端序网络字节序
        let total_len_bytes = total_len.to_be_bytes();
        packet[2] = total_len_bytes[0];
        packet[3] = total_len_bytes[1];

        // 生存时间 (TTL = 64)
        packet[8] = 64;

        // 协议类型 (Protocol)
        packet[9] = protocol as u8;

        // 源 IP 地址 (4字节)
        packet[12..16].copy_from_slice(&src_ip.octets());

        // 目的 IP 地址 (4字节)
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // 计算并写入 IP 头部的校验和（只校验前20字节）
        let ip_csum = Self::calc_checksum(&packet[0..20]);
        let ip_csum_bytes = ip_csum.to_be_bytes();
        packet[10] = ip_csum_bytes[0];
        packet[11] = ip_csum_bytes[1];

        packet[20..].copy_from_slice(&payload);

        packet
    }

    /// 获取源 IP 地址 (Source IP)
    pub fn get_source_ip(&self) -> Ipv4Addr {
        let addr_bytes: [u8; 4] = self.raw_data[12..16]
            .try_into()
            .expect("slice with incorrect length");
        Ipv4Addr::from(addr_bytes)
    }

    /// 获取目的 IP 地址 (Destination IP)
    pub fn get_destination_ip(&self) -> Ipv4Addr {
        let addr_bytes: [u8; 4] = self.raw_data[16..20]
            .try_into()
            .expect("slice with incorrect length");
        Ipv4Addr::from(addr_bytes)
    }

    /// 获取上层协议类型
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.raw_data[9])
    }

    /// 获取 payload
    pub fn payload(&self) -> &[u8] {
        &self.raw_data[20..]
    }
}
