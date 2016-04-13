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
