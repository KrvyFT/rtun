use std::net::Ipv4Addr;

use super::protocol::Checksum;

pub enum ICMPType {
    EchoReply = 0,              // Ping 回应
    DestinationUnreachable = 3, // 目标不可达
    SourceQuench = 4,           // 源抑制
    Redirect = 5,               // 路由重定向
    EchoRequest = 8,            // Ping 请求
    TimeExceeded = 11,          // 超时（比如 traceroute 路由追踪时会用到）
    Unknown = 255,              // 未知协议兜底
}

impl From<u8> for ICMPType {
    fn from(value: u8) -> Self {
        match value {
            0 => ICMPType::EchoReply,
            3 => ICMPType::DestinationUnreachable,
            4 => ICMPType::SourceQuench,
            5 => ICMPType::Redirect,
            8 => ICMPType::EchoRequest,
            11 => ICMPType::TimeExceeded,
            _ => ICMPType::Unknown,
        }
    }
}

pub struct ICMPPacket<'a> {
    // 借用自 IP 包的 payload 部分
    raw_data: &'a [u8],
}

impl<'a> Checksum for ICMPPacket<'a> {}

impl<'a> ICMPPacket<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self { raw_data: slice }
    }

    /// 获取 ICMP 类型 (Type)
    /// 第 0 个字节：8 代表 Ping 请求，0 代表 Ping 回应
    pub fn get_type(&self) -> ICMPType {
        ICMPType::from(self.raw_data[0])
    }

    /// 获取 ICMP 子类型 (Code)
    /// Ping 请求通常是 0
    /// Ping 超时（Time Exceeded）通常是 1
    pub fn get_code(&self) -> u8 {
        self.raw_data[1]
    }

    /// 获取完整的剩余数据
    pub fn payload(&self) -> &[u8] {
        &self.raw_data[4..]
    }

    /// 构建回复
    pub fn build_reply(request_data: &[u8]) -> Vec<u8> {
        let mut reply = request_data.to_vec();

        reply[0] = ICMPType::EchoReply as u8;
        reply[1] = 0;

        reply[2] = 0;
        reply[3] = 0;
        let checksum = Self::calc_checksum(&reply);

        let csum_bytes = checksum.to_be_bytes();
        reply[2] = csum_bytes[0];
        reply[3] = csum_bytes[1];
        reply
    }
}
