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

pub mod client;
pub mod sniffer;

use std::io::prelude::*;
use std::fs::{self, File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT, AtomicBool, ATOMIC_BOOL_INIT};
use std::cell::RefCell;

pub const MAX_CAPTURE: usize = 16_000_000 - 1;
static FILE_SIZE: AtomicUsize = ATOMIC_USIZE_INIT;
static CAP_ON: AtomicBool = ATOMIC_BOOL_INIT;
static QRY_CNT: AtomicUsize = ATOMIC_USIZE_INIT;
pub static CAP_FILE: &'static str = "spyglass-capture.dat";

thread_local!(static OUT: RefCell<File> =
    RefCell::new(OpenOptions::new().read(true).append(true).create(true).open(CAP_FILE).unwrap())
);

pub fn clear_cap() {
    debug!("deleting capture file {}", CAP_FILE);
    let _ = fs::remove_file(CAP_FILE);
}
pub fn set_cap(on: bool) { CAP_ON.store(on, Ordering::SeqCst) }
pub fn chk_cap() -> bool { CAP_ON.load(Ordering::SeqCst) }

fn write_cap(cap: &mut File, msg: &str) {
    debug!("captured: {}", msg);
    let bytes = match cap.write(msg.as_bytes()) {
        Ok(cnt) => cnt,
        Err(e) => panic!(e),
    };
    if FILE_SIZE.fetch_add(bytes, Ordering::SeqCst) + bytes > MAX_CAPTURE {
        set_cap(false);
    }
}

pub fn cap_size() -> usize { FILE_SIZE.load(Ordering::SeqCst) }

fn inc_qry() {
    QRY_CNT.fetch_add(1, Ordering::SeqCst);
}
pub fn qry_cnt() -> usize { QRY_CNT.load(Ordering::SeqCst) }
