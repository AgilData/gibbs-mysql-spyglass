use std::net::IpAddr;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
pub static TMP_FILE: &'static str = "gibbs-capture.dat";

#[derive(Clone, Debug)]
pub struct COpts {
    pub pin: u32,
    pub host: IpAddr,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub db: String,
    pub iface: String,
}

#[allow(dead_code)]
pub fn mk_ascii(arr: &[u8]) -> String {
let ascii: Vec<u8> = arr.iter()
                        .map(|b| match *b {
                            0u8 ... 32u8 | 127u8 ... 255u8 => 32u8,
                            c @ _ => c,
                        })
                        .collect();
    String::from_utf8(ascii).unwrap()
}
