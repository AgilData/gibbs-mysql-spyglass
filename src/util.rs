// Gibbs MySQL Spyglass
// Copyright (C) 2016 AgilData
//
// This file is part of Gibbs MySQL Spyglass.
//
// Gibbs MySQL Spyglass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Gibbs MySQL Spyglass is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Gibbs MySQL Spyglass.  If not, see <http://www.gnu.org/licenses/>.

extern crate ini;
use self::ini::Ini;

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct COpts {
    pub key: String,
    pub host: IpAddr,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub db: String,
    pub iface: String,
}

use std::env;

static CFG_FILE: &'static str = "spyglass.cfg";

fn dflt_opt() -> COpts {
    COpts {
        key: "".to_string(),
        host: IpAddr::V4(Ipv4Addr::new(0,0,0,0)),
        port: 3306,
        user: "root".to_string(),
        pass: "".to_string(),
        db: "mysql".to_string(),
        iface: "".to_string(),
    }
}

pub fn wr_opt(o: COpts) {
    let mut conf = Ini::new();
    conf.with_section(None::<String>)
        .set("key", o.key)
        .set("host", o.host.to_string())
        .set("port", o.port.to_string())
        .set("user", o.user)
        .set("db", o.db)
        .set("iface", o.iface);

    if conf.write_to_file(CFG_FILE).is_ok() {
        println!("Saved your configuration in {}/{}",
                 env::current_dir().unwrap().display(), CFG_FILE);
    }
}
use std::u16;

pub fn rd_opt() -> COpts {
    match Ini::load_from_file(CFG_FILE) {
        Ok(conf) => {
            println!("Reused your configuration from {}/{}",
                     env::current_dir().unwrap().display(), CFG_FILE);
            let sect = conf.section(None::<String>).unwrap();
            let mut o = dflt_opt();
            if let Some(v) = sect.get("key") { o.key = v.to_owned(); }
            if let Some(v) = sect.get("host") { o.host = v.parse().unwrap(); }
            if let Some(v) = sect.get("port") { o.port = v.parse().unwrap(); }
            if let Some(v) = sect.get("user") { o.user = v.to_owned(); }
            if let Some(v) = sect.get("db") { o.db = v.to_owned(); }
            if let Some(v) = sect.get("iface") { o.iface = v.to_owned(); }

            o
        },
        Err(_) => dflt_opt(),
    }
}

// read a one byte length-encoded integer
pub fn read_int1(pyld: &[u8]) -> u32 {
    pyld[0] as u32
}

// read a two byte length-encoded integer
pub fn read_int2(pyld: &[u8]) -> u32 {
    (pyld[0] as u32) +
    ((pyld[1] as u32) << 8)
}

// read a three byte length-encoded integer
pub fn read_int3(pyld: &[u8]) -> u32 {
    (pyld[0] as u32) +
    ((pyld[1] as u32) << 8) +
    ((pyld[2] as u32) << 16)
}

// read an eight byte length-encoded integer
#[allow(dead_code)]
pub fn read_int8(pyld: &[u8]) -> u64 {
        (pyld[0] as u64) +
        ((pyld[1] as u64) << 8) +
        ((pyld[2] as u64) << 16) +
        ((pyld[3] as u64) << 24) +
        ((pyld[4] as u64) << 32) +
        ((pyld[5] as u64) << 40) +
        ((pyld[6] as u64) << 48) +
        ((pyld[7] as u64) << 56)
}

pub fn mk_ascii(arr: &[u8]) -> String {
let ascii: Vec<u8> = arr.iter()
                        .map(|b| match *b {
                            0u8 ... 32u8 | 127u8 ... 255u8 => 32u8,
                            c @ _ => c,
                        })
                        .collect();
    String::from_utf8(ascii).unwrap()
}
