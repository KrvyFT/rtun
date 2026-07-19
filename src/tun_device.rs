use std::{
    fs::{File, OpenOptions},
    io::{self, Error, Read, Write},
    os::fd::AsRawFd,
};

use libc::{IFF_NO_PI, IFF_TUN, TUNSETIFF, c_short, ifreq};

pub struct TUNDevice {
    file: File,
}

impl TUNDevice {
    /// 创建并打开一个虚拟网卡
    pub fn new() -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("open /dev/net/tun failed: {}", e))?;

        let mut ifr: ifreq = unsafe { std::mem::zeroed() };

        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as c_short;

        let res = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                TUNSETIFF,
                &mut ifr as *mut ifreq as *mut libc::c_void,
            )
        };

        if res < 0 {
            return Err(format!(
                "ioctl TUNSETIFF failed: {}",
                Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }

    /// 从网卡里读取操作系统发过来的原始 IP 数据包
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.file.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(e),
        }
    }

    /// 往网卡里写入原始 IP 数据包，让操作系统处理
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self.file.write_all(&data) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// 关闭虚拟网卡
    pub fn down(self) {
        drop(self);
    }
}
