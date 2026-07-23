use std::{io, sync::Arc};

use tokio::sync::mpsc;

use crate::{
    protocol::{
        icmp_packet::{IcmpPacket, IcmpType},
        ip_packet::Ipv4Packet,
        port_registry::PortRegistry,
        protocol::Protocol,
        udp::udp_packet::UdpPacket,
    },
    tun_device::TunDevice,
};

mod protocol;
mod tun_device;

#[tokio::main]
async fn main() -> io::Result<()> {
    let tun = Arc::new(TunDevice::new().expect("Failed to create TUN device"));
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
    let registry = Arc::new(PortRegistry::new());
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
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let ip_packet = Ipv4Packet::new(&raw_packet);

            match ip_packet.protocol() {
                Protocol::Icmp => {
                    let icmp_packet = IcmpPacket::new(ip_packet.payload());

                    match icmp_packet.msg_type() {
                        IcmpType::EchoRequest => {
                            let reply = IcmpPacket::build_reply(ip_packet.payload());
                            let final_packet = Ipv4Packet::build_ipv4_packet(
                                ip_packet.destination_ip(),
                                ip_packet.source_ip(),
                                Protocol::Icmp,
                                &reply,
                            );
                            let _ = tx_clone.send(final_packet).await;
                        }
                        _ => {}
                    }
                }
                Protocol::Udp => {
                    let udp_packet = UdpPacket::new(ip_packet.payload());
                    let dest_port = udp_packet.destination_port();

                    if let Some(tx) = registry.get(dest_port) {
                        let _ = tx.try_send((
                            ip_packet.source_ip(),
                            udp_packet.source_port(),
                            udp_packet.payload().to_vec(),
                        ));
                    } else {
                        println!(
                            "Receive UDP packets sent to unbound port {} and discard them automatically",
                            dest_port
                        );
                    }
                }
                Protocol::Unknown => {}
            }
        });
    }
}
