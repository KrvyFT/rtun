use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc;

pub type UdpPacketMessage = (Ipv4Addr, u16, Vec<u8>);

pub struct PortRegistry {
    sockets: Arc<Mutex<HashMap<u16, mpsc::Sender<UdpPacketMessage>>>>,
}

impl PortRegistry {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// bind port
    pub fn register(&self, port: u16, tx: mpsc::Sender<UdpPacketMessage>) -> Result<(), String> {
        let mut map = self.sockets.lock().unwrap();
        if map.contains_key(&port) {
            return Err(String::from("port already bound"));
        }
        map.insert(port, tx);
        Ok(())
    }

    /// unbind
    pub fn unregister(&self, port: u16) -> Result<(), String> {
        let mut map = self.sockets.lock().unwrap();
        map.remove(&port);
        Ok(())
    }

    /// get sender by port
    pub fn get(&self, port: u16) -> Option<mpsc::Sender<UdpPacketMessage>> {
        let map = self.sockets.lock().unwrap();
        map.get(&port).cloned()
    }
}
