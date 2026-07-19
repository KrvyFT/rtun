use std::net::Ipv4Addr;

use crate::protocol::icmp_packet::ICMPPacket;

pub struct UdpPacket<'a> {
    raw_data: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self { raw_data: slice }
    }
}
