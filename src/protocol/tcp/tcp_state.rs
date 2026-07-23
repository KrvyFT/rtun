use crate::protocol::tcp::tcp_flags::TcpFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynRcvd,
    Established,
}
pub enum TcpAction {
    SendSynAck { seq: u32, ack: u32 },
    SendRst { seq: u32, ack: Option<u32> },
    Establish { seq: u32, ack: u32 },
    Closed,
    None,
}

pub struct Connection {
    pub state: TcpState,
    pub iss: u32,
    pub snd_nxt: u32,
    pub irs: u32,
    pub rcv_nxt: u32,
}

impl Connection {
    pub fn new_listening() -> Self {
        Self {
            state: TcpState::Listen,
            iss: 0,
            snd_nxt: 0,
            irs: 0,
            rcv_nxt: 0,
        }
    }

    pub fn step(&mut self, seq: u32, ack: u32, flags: TcpFlags, payload_len: usize) -> TcpAction {
        if flags.rst {
            match self.state {
                TcpState::Listen => {
                    // RFC 793: 处于 LISTEN 状态下的连接如果收到 RST，应直接忽略，保持 LISTEN 状态
                    return TcpAction::None;
                }
                TcpState::SynRcvd => {
                    // RFC 793: 被动打开的连接在 SYN-RECEIVED 收到 RST，应回退到 LISTEN
                    println!("💥 SYN_RCVD 收到 RST 报文，连接回退至 LISTEN 状态");
                    self.state = TcpState::Listen;
                    return TcpAction::None;
                }
                TcpState::Closed => {
                    // 已经在 CLOSED 状态，直接丢弃 RST
                    return TcpAction::None;
                }
                _ => {
                    println!("💥 收到对方的 RST 报文，直接将连接标记为 CLOSED");
                    self.state = TcpState::Closed;
                    return TcpAction::Closed;
                }
            }
        }

        match self.state {
            TcpState::Listen => {
                if flags.syn && !flags.ack {
                    self.irs = seq;
                    self.rcv_nxt = seq.wrapping_add(1);

                    self.iss = 5000;
                    self.snd_nxt = self.iss.wrapping_add(1);

                    self.state = TcpState::SynRcvd;

                    return TcpAction::SendSynAck {
                        seq: self.iss,
                        ack: self.rcv_nxt,
                    };
                }

                if flags.ack {
                    return TcpAction::SendRst {
                        seq: ack, // 根据 RFC 793：如果入包有 ACK，新包 seq = in.ack
                        ack: None,
                    };
                }
                TcpAction::None
            }
            TcpState::SynRcvd => {
                if flags.ack && !flags.syn {
                    if ack == self.snd_nxt {
                        self.state = TcpState::Established;
                        return TcpAction::Establish {
                            seq: self.snd_nxt,
                            ack: self.rcv_nxt,
                        };
                    } else {
                        return TcpAction::SendRst {
                            seq: ack,
                            ack: None,
                        };
                    }
                }
                TcpAction::None
            }

            TcpState::Established => TcpAction::None,
            TcpState::Closed => Self::build_rst_for_closed(seq, ack, flags, payload_len),
        }
    }

    pub fn build_rst_for_closed(
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload_len: usize,
    ) -> TcpAction {
        if flags.ack {
            // 入包有 ACK -> seq = incoming_ack, 不带 ACK
            TcpAction::SendRst {
                seq: ack,
                ack: None,
            }
        } else {
            // 入包无 ACK -> seq = 0, ack = incoming_seq + len + (1 if syn) + (1 if fin), 带 ACK
            let mut consumed_len = payload_len as u32;
            if flags.syn {
                consumed_len += 1;
            }
            if flags.fin {
                consumed_len += 1;
            }
            TcpAction::SendRst {
                seq: 0,
                ack: Some(seq.wrapping_add(consumed_len)),
            }
        }
    }
}
