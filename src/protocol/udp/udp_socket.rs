use std::{io, net::Ipv4Addr};

use tokio::sync::mpsc;

use crate::protocol::{
    ip_packet::Ipv4Packet,
    port_registry::{PortRegistry, UdpPacketMessage},
    protocol::Protocol,
    udp::udp_packet::UdpPacket,
};

pub struct UdpSocket {
    port: u16,
    rx: mpsc::Receiver<UdpPacketMessage>,
    rx_to_tun: mpsc::Sender<Vec<u8>>,
    registry: PortRegistry,
    local_ip: Ipv4Addr,
}

impl UdpSocket {
    fn new(
        port: u16,
        registry: PortRegistry,
        rx_to_tun: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel(128);
        registry.register(port, tx)?;
        Ok(Self {
            port,
            rx,
            rx_to_tun,
            registry,
            local_ip: Ipv4Addr::new(10, 0, 0, 1),
        })
    }

    pub async fn recv_from(&mut self) -> Option<UdpPacketMessage> {
        self.rx.recv().await
    }

    pub async fn send_to(&self, buf: &[u8], dst: Ipv4Addr, dst_port: u16) -> io::Result<()> {
        let udp_payload = UdpPacket::build_reply(self.local_ip, dst, self.port, dst_port, buf);

        let final_packet =
            Ipv4Packet::build_ipv4_packet(dst, self.local_ip, Protocol::Udp, &udp_payload);

        self.rx_to_tun
            .send(final_packet)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TUN 网卡写入管道已断开"))?;

        Ok(())
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = self.registry.unregister(self.port);
    }
}
