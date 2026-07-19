use std::io;

use crate::{
    protocol::{
        icmp_packet::{ICMPPacket, ICMPType},
        ip_packet::IPV4Packet,
        protocol::Protocol,
        udp_packet::UdpPacket,
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
                        let reply = ICMPPacket::build_reply(ip_packet.payload());

                        let final_packet = IPV4Packet::build_ipv4_packet(
                            ip_packet.get_destination_ip(), // 新源 IP
                            ip_packet.get_source_ip(),      // 新目的 IP
                            Protocol::ICMP,                 // 协议类型
                            &reply, // 刚做好的 ICMP 响应包作为 IP 的 payload
                        );

                        tun.write(&final_packet)?;
                    }
                    _ => {}
                }
            }
            Protocol::UDP => {
                let udp_packet = UdpPacket::new(ip_packet.payload());

                let udp_reply = UdpPacket::build_udp_packet(
                    ip_packet.get_destination_ip(),
                    ip_packet.get_source_ip(),
                    udp_packet.get_destination_port(),
                    udp_packet.get_source_port(),
                    udp_packet.payload(),
                );

                let final_packet = IPV4Packet::build_ipv4_packet(
                    ip_packet.get_destination_ip(), // 新源 IP
                    ip_packet.get_source_ip(),      // 新目的 IP
                    Protocol::UDP,                  // 协议类型
                    &udp_reply,                     // 刚做好的 UDP 响应包作为 IP 的 payload
                );

                // 🔥 修复点：一定要把拼装好的 IP 层数据包写回网卡，否则内核收不到响应
                tun.write(&final_packet)?;
            }
            Protocol::Unknown => todo!(),
        }
    }
}
