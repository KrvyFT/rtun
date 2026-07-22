use std::{io, sync::Arc};

use tokio::sync::mpsc;

use crate::{
    protocol::{
        icmp_packet::{ICMPPacket, ICMPType},
        ip_packet::Ipv4Packet,
        protocol::Protocol,
        udp::udp_packet::UdpPacket,
    },
    tun_device::TUNDevice,
};

mod protocol;
mod tun_device;

#[tokio::main]
async fn main() -> io::Result<()> {
    let tun = Arc::new(TUNDevice::new().expect("Failed to create TUN device"));
    println!("TUN device created successfully");

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let tun_writer = Arc::clone(&tun);
    tokio::spawn(async move {
        while let Some(packet_to_write) = rx.recv().await {
            if let Err(e) = tun_writer.write(&packet_to_write).await {
                eprintln!("write error: {:?}", e);
            }
        }
    });

    let mut buf = [0u8; 1500];
    loop {
        let bytes_read = tun.read(&mut buf).await?;
        let raw_packet = buf[..bytes_read].to_vec();
        if raw_packet.is_empty() {
            continue;
        }

        // 仅处理 IPv4 数据包 (IP Version = 4)
        if raw_packet[0] >> 4 != 4 {
            continue;
        }

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let ip_packet = Ipv4Packet::new(&raw_packet);

            match ip_packet.protocol() {
                Protocol::ICMP => {
                    let icmp_packet = ICMPPacket::new(ip_packet.payload());

                    match icmp_packet.get_type() {
                        ICMPType::EchoRequest => {
                            let reply = ICMPPacket::build_reply(ip_packet.payload());
                            let final_packet = Ipv4Packet::build_ipv4_packet(
                                ip_packet.get_destination_ip(),
                                ip_packet.get_source_ip(),
                                Protocol::ICMP,
                                &reply,
                            );
                            let _ = tx_clone.send(final_packet).await;
                        }
                        _ => {}
                    }
                }
                Protocol::UDP => {
                    let udp_packet = UdpPacket::new(ip_packet.payload());
                    let udp_reply = UdpPacket::build_reply(
                        ip_packet.get_destination_ip(),
                        ip_packet.get_source_ip(),
                        udp_packet.get_destination_port(),
                        udp_packet.get_source_port(),
                        udp_packet.payload(),
                    );
                    let final_packet = Ipv4Packet::build_ipv4_packet(
                        ip_packet.get_destination_ip(),
                        ip_packet.get_source_ip(),
                        Protocol::UDP,
                        &udp_reply,
                    );
                    let _ = tx_clone.send(final_packet).await;
                }
                Protocol::Unknown => {}
            }
        });
    }
}
