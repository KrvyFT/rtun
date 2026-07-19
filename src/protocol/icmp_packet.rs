use std::net::Ipv4Addr;

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

    pub fn build_icmp_reply(&self, src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Vec<u8> {
        let icmp_reply_data = Self::build_reply(self.raw_data);

        // IPv4 头部 20 字节 + 完整 ICMP 长度
        let total_len = 20 + icmp_reply_data.len();
        let mut packet = vec![0u8; total_len];

        // 写入版本号 (4) 和头部长度 (5, 代表 5 个 32位字 = 20字节)
        packet[0] = 0x45;

        // 写入总长度 (Total Length)，大端序网络字节序
        let total_len_bytes = (total_len as u16).to_be_bytes();
        packet[2] = total_len_bytes[0];
        packet[3] = total_len_bytes[1];

        // 写入生存时间 (TTL = 64)
        packet[8] = 64;

        // 写入协议类型 (Protocol = 1 代表 ICMP)
        packet[9] = 1;

        // 写入源 IP 地址 (4字节)
        packet[12..16].copy_from_slice(&src_ip.octets());

        // 写入目的 IP 地址 (4字节)
        packet[16..20].copy_from_slice(&dest_ip.octets());

        // 计算并写入 IP 头部的校验和（只校验前20字节）
        let ip_csum = ICMPPacket::calc_checksum(&packet[0..20]);
        let ip_csum_bytes = ip_csum.to_be_bytes();
        packet[10] = ip_csum_bytes[0];
        packet[11] = ip_csum_bytes[1];

        // 把信件内容（ICMP 载荷）紧跟在 20 字节头部后面塞进去
        packet[20..].copy_from_slice(&icmp_reply_data);

        packet
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

    /// 计算校验和
    pub fn calc_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;

        while i < data.len() - 1 {
            let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
            sum += word;
            i += 2;
        }

        if i < data.len() {
            let word = (data[i] as u32) << 8;
            sum += word;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }
}
