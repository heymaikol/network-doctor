//! Finds devices on this computer's own network, without admin rights.
//!
//! Like Network Doctor's device map, it only makes ordinary TCP connections:
//! one round to ports 80 and 443 on each address of the local /24. A device
//! that accepts or refuses either one is there. Devices that stay silent on
//! both but answered the address lookup (ARP) the connects caused are listed
//! too, from the kernel's neighbour table. Nothing is sent after a connect.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long one connect may take. Windows retries a refused connect for up to
/// two seconds before reporting it, so a shorter wait there would read every
/// refusal as silence and miss devices that are present with the port closed.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(if cfg!(windows) { 2500 } else { 700 });
const WORKERS: usize = 64;

/// The fixed list a device is asked about, with each port's usual use. The
/// name is the port's registered service, not proof of what the device is.
pub const SERVICES: [(u16, &str); 15] = [
    (80, "Web page"),
    (443, "Secure web page"),
    (22, "SSH (remote terminal)"),
    (445, "Windows file sharing"),
    (631, "Printing (IPP)"),
    (9100, "Printing (JetDirect)"),
    (515, "Printing (LPD)"),
    (3389, "Remote Desktop"),
    (5900, "Screen sharing (VNC)"),
    (2049, "NFS file sharing"),
    (53, "DNS"),
    (21, "FTP"),
    (23, "Telnet"),
    (8080, "Web page (port 8080)"),
    (8443, "Secure web page (port 8443)"),
];

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub name: Option<String>,
    /// Accepted a connection on 80 or 443.
    pub web: bool,
    pub is_me: bool,
    pub is_router: bool,
    /// Which of the fixed ports it answers on, and whether any refused
    /// (there, with nothing listening) as opposed to staying silent.
    pub offers: Option<(Vec<u16>, bool)>,
}

impl Device {
    /// What it offers, in a few words, for the list.
    pub fn tags(&self) -> Vec<&'static str> {
        let Some((ports, _)) = &self.offers else {
            return vec![];
        };
        let mut tags: Vec<&'static str> = Vec::new();
        for p in ports {
            let t = match p {
                80 | 443 | 8080 | 8443 => "web page",
                22 => "SSH",
                445 | 2049 => "file sharing",
                631 | 9100 | 515 => "printing",
                3389 => "remote desktop",
                5900 => "screen sharing",
                53 => "DNS",
                21 => "FTP",
                23 => "Telnet",
                _ => continue,
            };
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
        tags
    }
}

pub enum Msg {
    Progress(usize, usize),
    Found(Device),
    Name(Ipv4Addr, String),
    Done {
        cancelled: bool,
    },
    /// What a device answers on (see `Device::offers`).
    Services {
        ip: Ipv4Addr,
        open: Vec<u16>,
        refused: bool,
    },
}

/// This computer's address on the network it reaches the internet through.
/// Connecting a UDP socket sends nothing; it only asks the kernel for the route.
pub fn my_address() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// Only home and office style private networks are scanned: on a public
/// address the neighbouring addresses belong to other people.
pub fn scannable(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

/// The 254 usable addresses of `ip`'s /24.
pub fn subnet(ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let [a, b, c, _] = ip.octets();
    (1..=254).map(|d| Ipv4Addr::new(a, b, c, d)).collect()
}

pub fn subnet_label(ip: Ipv4Addr) -> String {
    let [a, b, c, _] = ip.octets();
    format!("{a}.{b}.{c}.1 to {a}.{b}.{c}.254")
}

/// The router's address. Read from the kernel's route table on Linux; other
/// systems have no file to read it from, so the router is listed unlabelled.
#[cfg(target_os = "linux")]
fn default_gateway() -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_gateway(&text)
}

#[cfg(not(target_os = "linux"))]
fn default_gateway() -> Option<Ipv4Addr> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_gateway(text: &str) -> Option<Ipv4Addr> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            return None;
        }
        // Little-endian hex.
        let n = u32::from_str_radix(f[2], 16).ok()?;
        (n != 0).then(|| Ipv4Addr::from(n.swap_bytes()))
    })
}

/// Addresses that answered ARP, from the kernel's neighbour table. Linux only:
/// elsewhere a device that stays silent on both web ports is not listed.
#[cfg(target_os = "linux")]
fn neighbours() -> Vec<Ipv4Addr> {
    parse_neighbours(&std::fs::read_to_string("/proc/net/arp").unwrap_or_default())
}

#[cfg(not(target_os = "linux"))]
fn neighbours() -> Vec<Ipv4Addr> {
    Vec::new()
}

#[cfg(any(target_os = "linux", test))]
fn parse_neighbours(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Flags 0x2 = a completed entry; an all-zero MAC never answered.
            (f.len() >= 4 && f[2] != "0x0" && f[3] != "00:00:00:00:00:00")
                .then(|| f[0].parse().ok())?
        })
        .collect()
}

#[derive(PartialEq)]
enum Answer {
    Open,
    Refused,
    Silent,
}

fn knock(ip: Ipv4Addr, port: u16) -> Answer {
    match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), CONNECT_TIMEOUT) {
        Ok(_) => Answer::Open,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Answer::Refused,
        Err(_) => Answer::Silent,
    }
}

/// The device's name from reverse DNS (which on most home networks is the
/// router's list of device names), if it has one. Linux only for now: the
/// lookup goes through the C library, whose address layout differs per system.
#[cfg(not(target_os = "linux"))]
fn reverse_name(_ip: Ipv4Addr) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn reverse_name(ip: Ipv4Addr) -> Option<String> {
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    let mut host = [0 as libc::c_char; 256];
    // SAFETY: `sa` and `host` outlive the call and their sizes are passed with them.
    let rc = unsafe {
        libc::getnameinfo(
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo wrote a NUL-terminated string on success.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    // The name comes from the network: keep it to plain hostname characters.
    let name: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-._".contains(*c))
        .take(64)
        .collect();
    // "_gateway" and the like are made up by this computer, not the device's own name.
    (!name.is_empty() && !name.starts_with('_')).then_some(name)
}

/// Sweep this computer's /24. Results arrive on `tx`; `wake` is called after each.
pub fn sweep(
    me: Ipv4Addr,
    tx: Sender<Msg>,
    cancel: Arc<AtomicBool>,
    wake: impl Fn() + Send + Sync + 'static,
) {
    std::thread::spawn(move || {
        let wake = Arc::new(wake);
        let router = default_gateway();
        let targets = subnet(me);
        let total = targets.len();
        let queue = Arc::new(Mutex::new(targets));
        let done = Arc::new(AtomicUsize::new(0));
        let found: Arc<Mutex<BTreeMap<Ipv4Addr, Device>>> = Arc::default();
        let make = move |ip: Ipv4Addr, web: bool| Device {
            ip,
            name: None,
            web,
            is_me: ip == me,
            is_router: Some(ip) == router,
            offers: None,
        };

        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let (queue, done, found, tx, cancel, wake) = (
                    queue.clone(),
                    done.clone(),
                    found.clone(),
                    tx.clone(),
                    cancel.clone(),
                    wake.clone(),
                );
                std::thread::spawn(move || {
                    loop {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        let Some(ip) = queue.lock().unwrap().pop() else {
                            return;
                        };
                        if ip == me {
                            found.lock().unwrap().insert(ip, make(ip, false));
                            let _ = tx.send(Msg::Found(make(ip, false)));
                        } else {
                            let (a, b) = (knock(ip, 80), knock(ip, 443));
                            if a != Answer::Silent || b != Answer::Silent {
                                let d = make(ip, a == Answer::Open || b == Answer::Open);
                                found.lock().unwrap().insert(ip, d.clone());
                                let _ = tx.send(Msg::Found(d));
                            }
                        }
                        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = tx.send(Msg::Progress(n, total));
                        wake();
                    }
                })
            })
            .collect();
        for w in workers {
            let _ = w.join();
        }
        let cancelled = cancel.load(Ordering::Relaxed);
        if !cancelled {
            // Devices that kept quiet on 80 and 443 but answered ARP.
            let [a, b, c, _] = me.octets();
            for ip in neighbours() {
                let same_net = ip.octets()[..3] == [a, b, c];
                if same_net && !found.lock().unwrap().contains_key(&ip) {
                    let d = make(ip, false);
                    found.lock().unwrap().insert(ip, d.clone());
                    let _ = tx.send(Msg::Found(d));
                }
            }
            wake();
            let ips: Vec<Ipv4Addr> = found.lock().unwrap().keys().copied().collect();
            // What each one offers, a few devices at a time.
            for group in ips.chunks(16) {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let jobs: Vec<_> = group
                    .iter()
                    .map(|&ip| {
                        let (tx, wake) = (tx.clone(), wake.clone());
                        std::thread::spawn(move || {
                            let (open, refused) = ask(ip);
                            let _ = tx.send(Msg::Services { ip, open, refused });
                            wake();
                        })
                    })
                    .collect();
                for j in jobs {
                    let _ = j.join();
                }
            }
            // Names, looked up side by side: a lookup can take seconds.
            let lookups: Vec<_> = ips
                .into_iter()
                .map(|ip| {
                    let (tx, wake) = (tx.clone(), wake.clone());
                    std::thread::spawn(move || {
                        if let Some(name) = reverse_name(ip) {
                            let _ = tx.send(Msg::Name(ip, name));
                            wake();
                        }
                    })
                })
                .collect();
            for l in lookups {
                let _ = l.join();
            }
        }
        let _ = tx.send(Msg::Done { cancelled });
        wake();
    });
}

/// Ask one device which of the fixed ports it answers on, all at once.
pub fn services(ip: Ipv4Addr, tx: Sender<Msg>, wake: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let (open, refused) = ask(ip);
        let _ = tx.send(Msg::Services { ip, open, refused });
        wake();
    });
}

/// One round of connects to the fixed ports, side by side.
fn ask(ip: Ipv4Addr) -> (Vec<u16>, bool) {
    let asks: Vec<_> = SERVICES
        .iter()
        .map(|&(port, _)| std::thread::spawn(move || (port, knock(ip, port))))
        .collect();
    let answers: Vec<(u16, Answer)> = asks.into_iter().filter_map(|a| a.join().ok()).collect();
    let open = answers
        .iter()
        .filter(|(_, a)| *a == Answer::Open)
        .map(|(p, _)| *p)
        .collect();
    let refused = answers.iter().any(|(_, a)| *a == Answer::Refused);
    (open, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_private_networks_are_scanned() {
        assert!(scannable(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(scannable(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(scannable(Ipv4Addr::new(172, 16, 4, 4)));
        assert!(!scannable(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!scannable(Ipv4Addr::new(203, 0, 113, 7)));
        // Carrier-grade NAT space is shared with strangers.
        assert!(!scannable(Ipv4Addr::new(100, 64, 0, 9)));
    }

    #[test]
    fn subnet_is_one_slash_24() {
        let s = subnet(Ipv4Addr::new(192, 168, 7, 99));
        assert_eq!(s.len(), 254);
        assert_eq!(s[0], Ipv4Addr::new(192, 168, 7, 1));
        assert_eq!(s[253], Ipv4Addr::new(192, 168, 7, 254));
        assert_eq!(
            subnet_label(Ipv4Addr::new(192, 168, 7, 99)),
            "192.168.7.1 to 192.168.7.254"
        );
    }

    #[test]
    fn reads_kernel_tables() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n\
                     wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n";
        assert_eq!(parse_gateway(route), Some(Ipv4Addr::new(192, 168, 1, 1)));
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n\
                   192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        assert_eq!(parse_neighbours(arp), [Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn asks_what_a_device_offers() {
        // This computer, with one listener: every other port refuses.
        let l = std::net::TcpListener::bind("127.0.0.1:8443").ok();
        let (open, refused) = ask(Ipv4Addr::LOCALHOST);
        if l.is_some() {
            assert!(open.contains(&8443));
        }
        assert!(refused);
        let d = Device {
            ip: Ipv4Addr::LOCALHOST,
            name: None,
            web: false,
            is_me: true,
            is_router: false,
            offers: Some((vec![80, 443, 631, 9100, 22], false)),
        };
        assert_eq!(d.tags(), ["web page", "printing", "SSH"]);
    }

    #[test]
    fn knocking_tells_open_from_refused() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(knock(Ipv4Addr::LOCALHOST, port) == Answer::Open);
        drop(l);
        // A freed ephemeral port can become another test's outgoing source port,
        // which then connects back to itself. Port 1 is never ephemeral.
        assert!(knock(Ipv4Addr::LOCALHOST, 1) == Answer::Refused);
    }
}
