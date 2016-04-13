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

use std::net::IpAddr;
use std::sync::mpsc::Sender;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
pub static TMP_FILE: &'static str = "spyglass-capture.dat";

#[derive(Clone, Debug)]
pub struct COpts {
    pub key: String,
    pub host: IpAddr,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub db: String,
    pub iface: String,
    pub tx: Option<Sender<u8>>,
}

// read a one byte length-encoded integer
pub fn read_int1(pyld: &[u8]) -> u32 {
    pyld[0] as u32
}

// read a two byte length-encoded integer
pub fn read_int2(pyld: &[u8]) -> u32 {
    let n: usize =
        (pyld[0] as usize) +
        ((pyld[1] as usize) << 8);
    n as u32
}

// read a three byte length-encoded integer
pub fn read_int3(pyld: &[u8]) -> u32 {
    let n: usize =
        (pyld[0] as usize) +
        ((pyld[1] as usize) << 8) +
        ((pyld[2] as usize) << 16);
    n as u32
}

// read an eight byte length-encoded integer
#[allow(dead_code)]
pub fn read_int8(pyld: &[u8]) -> u64 {
    let n: usize =
        (pyld[0] as usize) +
        ((pyld[1] as usize) << 8) +
        ((pyld[2] as usize) << 16) +
        ((pyld[3] as usize) << 24) +
        ((pyld[4] as usize) << 32) +
        ((pyld[5] as usize) << 40) +
        ((pyld[6] as usize) << 48) +
        ((pyld[7] as usize) << 56);
    n as u64
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
