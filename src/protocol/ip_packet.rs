use std::net::Ipv4Addr;

use crate::protocol::protocol::Protocol;

#[derive(Debug)]
pub struct IPV4Packet<'a> {
    raw_data: &'a [u8],
}

impl<'a> IPV4Packet<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        IPV4Packet { raw_data: slice }
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
