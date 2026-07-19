use std::io;

use crate::{
    protocol::{
        icmp_packet::{ICMPPacket, ICMPType},
        ip_packet::IPV4Packet,
        protocol::Protocol,
    },
    tun_device::TUNDevice,
};

mod protocol;
mod tun_device;

fn main() -> io::Result<()> {
    let mut tun = TUNDevice::new().expect("Failed to create TUN device");
    println!("TUN device created successfully");

    let mut buf = [0u8; 1500];
    loop {
        let bytes_read = tun.read(&mut buf)?;
        let raw_packet = &buf[..bytes_read];

        if raw_packet.is_empty() {
            continue;
        }

        // 仅处理 IPv4 数据包 (IP Version = 4)
        if raw_packet[0] >> 4 != 4 {
            continue;
        }

        let ip_packet = IPV4Packet::new(&raw_packet);

        match ip_packet.protocol() {
            Protocol::ICMP => {
                let icmp_packet = ICMPPacket::new(ip_packet.payload());

                match icmp_packet.get_type() {
                    ICMPType::EchoRequest => {
                        let reply = icmp_packet.build_icmp_reply(
                            ip_packet.get_destination_ip(), // 回复的源 IP 是原来的目的 IP
                            ip_packet.get_source_ip(),      // 回复的目的 IP 是原来的源 IP
                        );
                        tun.write(&reply)?;
                    }
                    _ => {}
                }
            }
            Protocol::Unknown => todo!(),
        }
    }
}
