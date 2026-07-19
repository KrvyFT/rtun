use std::{
    fs::{File, OpenOptions},
    io::{self, Error, Read, Write},
    os::fd::AsRawFd,
};

use libc::{IFF_NO_PI, IFF_TUN, TUNSETIFF, c_short, ifreq};
use tokio::io::unix::AsyncFd;

pub struct TUNDevice {
    async_fd: AsyncFd<File>,
}

impl TUNDevice {
    /// 创建并打开一个虚拟网卡
    pub fn new() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let fd = file.as_raw_fd();
        // 如果不设为非阻塞，AsyncFd 在 await 时依然会卡死底层工作线程
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

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
            return Err(io::Error::last_os_error());
        }
        Ok(TUNDevice {
            async_fd: AsyncFd::new(file)?,
        })
    }

    /// 从网卡里读取操作系统发过来的原始 IP 数据包
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let res =
                    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

                if res < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// 往网卡里写入原始 IP 数据包，让操作系统处理
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.async_fd.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let res =
                    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

                if res < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
