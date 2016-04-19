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

use super::{OUT, chk_cap, write_cap, inc_qry};

use util::{COpts, mk_ascii, read_int1, read_int2, read_int3};

use std::io::Write;
use std::net::IpAddr;
use std::str;

use time;

extern crate pnet;
use self::pnet::packet::{Packet};
use self::pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use self::pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use self::pnet::packet::ipv4::{Ipv4Packet};
use self::pnet::packet::udp::{UdpPacket};
use self::pnet::datalink::{datalink_channel};
use self::pnet::datalink::DataLinkChannelType::{Layer2};
use self::pnet::util::{NetworkInterface, get_network_interfaces};

use std::cmp;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local!(static STATES: RefCell<HashMap<u16, PcktState>> =
    RefCell::new(HashMap::new())
);

#[derive(Clone, Debug)]
enum MySQLState {
    Wait,
    Query { seq: u8, },
    Columns { seq: u8, num: u32, cnt: u32, },
    Rows { seq: u8, cnt: u32, },
}

#[derive(Clone, Debug)]
enum PcktState {
    Start { lst: MySQLState, },
    Frag { need: usize, part: Vec<u8>, seq: u8, lst: MySQLState, },
}

fn state_act(c2s: bool, nxt_seq: u8, lst: MySQLState, pyld: &[u8]) -> (MySQLState, Option<String>) {
    debug!("state_act() in: c2s={:?}, nxt_seq={:?}, lst={:?}, pyld={:?}", c2s, nxt_seq, lst, pyld);
    let redact = regex!(r#"(?x)( (?P<p>[\s=\(\+-/\*]) (
                            '[^'\\]*((\\.|'')[^'\\]*)*' |
                            "[^"\\]*((\\.|"")[^"\\]*)*" |
                            [\.][\d]+ | [\d][\.\d]*
                        ) )"#);

    match lst {
        MySQLState::Wait => {
            if c2s && nxt_seq == 0 && pyld[0] == 3 {
                let qry = &pyld[1..];
                match str::from_utf8(qry) {
                    Ok(x) => {
                        let cr = redact.replace_all(&x, "$p?");
                        inc_qry();
                        printfl!(".");
                        (MySQLState::Query { seq: nxt_seq, }, Some(format!("TYPE: QUERY\tSQL:\n{}", cr)))
                    },
                    Err(e) => {
                        debug!("redact failed for {:?} with error: {:?}", mk_ascii(qry), e);
                        (MySQLState::Wait, None)
                    }
                }
            } else {
                (MySQLState::Wait, None)
            }
        },

        MySQLState::Query { seq, } => {
            if c2s || nxt_seq != 1 {
                state_act(c2s, 0, MySQLState::Wait, pyld)
            } else {
                match pyld[0] {
                    0x00 | 0xfe => (MySQLState::Wait, Some(String::from("TYPE: QUERY_OK"))),
                    0xff => (MySQLState::Wait, Some(String::from("TYPE: QUERY_ERROR"))),
                    0xfc => (MySQLState::Columns { seq: nxt_seq, num: read_int2(&pyld[1..]), cnt: 0, }, None),
                    0xfd => (MySQLState::Columns { seq: nxt_seq, num: read_int3(&pyld[1..]), cnt: 0, }, None),
                    _ => (MySQLState::Columns { seq: nxt_seq, num: read_int1(pyld), cnt: 0,  }, None)
                }
            }
        },

        MySQLState::Columns { seq, num, cnt, }=> {
            if c2s {
                state_act(c2s, 0, MySQLState::Wait, pyld)
            } else {
                match pyld[0] {
                    // columns are followed by an EOF_Packet, then the rows
                    0xfe => (MySQLState::Rows { seq: nxt_seq, cnt: 0, }, None),
                    _ => (MySQLState::Columns { seq: nxt_seq, num: num, cnt: cnt + 1, }, None)
                }
            }
        },

        MySQLState::Rows { seq, cnt, } => {
            if c2s {
                state_act(c2s, 0, MySQLState::Wait, pyld)
            } else {
                match pyld[0] {
                    0x00 =>
                        // As of MySQL 5.7.5, OK packes are also used to indicate EOF, and EOF packets are deprecated.
                        (MySQLState::Wait, Some(String::from("TYPE: RESULT_SET"))),
                    0xfe => {
                        // EOF_Packet may contain useful information on index usage depending on
                        // the protocol version and configuration in use
                        let flg0 = if pyld.len() > 3 { pyld[3] } else { 0 };
                        let flg1 = if pyld.len() > 4 { pyld[4] } else { 0 };
                        (MySQLState::Wait, Some(format!("TYPE: RESULT_SET\tROW_COUNT: {}\tQUERY_SLOW: {}\tNO_INDEX_USED: {}\tNO_GOOD_INDEX_USED: {}",
                                    cnt, flg1 & 0x08 != 0, flg0 & 0x20 != 0, flg0 & 0x10 != 0)))
                    },
                    0xff => (MySQLState::Wait, Some(String::from("TYPE: QUERY_ERROR"))),
                    _ => (MySQLState::Rows { seq: nxt_seq, cnt: cnt + 1, }, None)
                }
            }
        },

    }
}

fn mysql_frag(need: usize, bs: &[u8]) -> (usize, usize, &[u8]) {
    let used = cmp::min(need, bs.len());
    let pyld = &bs[0..used];
    let need = need - used;
    debug!("mysql_frag() out: used={:?}, need={:?}, pyld={:?}", used, need, mk_ascii(pyld));
    (used, need, pyld)
}

fn mysql_packet_length(bs: &[u8]) -> usize {
    (bs[0] as usize) + ((bs[1] as usize) << 8) + ((bs[2] as usize) << 16)
}

fn mysql_next(bs: &[u8]) -> (usize, usize, u8, &[u8]) {
    match bs.len() {
        0 ... 3 => {
            // not enough bytes to know how many bytes we need beyond the header
            let used = bs.len();
            let need = 4 - used;
            let pyld = &bs[0..used];
            (used, need, 0, pyld)
        },
        _ => {
            let len = mysql_packet_length(bs);
            let seq: u8 = bs[3];
            let used = cmp::min(4 + len, bs.len());
            let pyld = &bs[0..used];
            let need = len + 4 - used;
            (used, need, seq, pyld)
        }
    }
}

fn nxt_state(c2s: bool, st: PcktState, bs: &[u8]) -> (usize, PcktState, Option<String>) {
    debug!("nxt_state() in: c2s={:?}, st={:?}, bs={:?}", c2s, st, bs);
    match st {
        PcktState::Start { lst, } => {
            match lst {
                MySQLState::Wait if !c2s => (bs.len(), PcktState::Start { lst: lst, }, None),
                _ => {
                    let (used, need, seq, pyld) = mysql_next(bs);
                    if need == 0 && pyld.len() > 4 {
                        let (nxt, out) = state_act(c2s, seq, lst, &pyld[4..]);
                        (used, PcktState::Start { lst: nxt, }, out)
                    } else {
                        let mut v: Vec<u8> = Vec::new();
                        v.extend_from_slice(pyld);
                        (used, PcktState::Frag { need: need, part: v, seq: seq, lst: lst }, None)
                    }
                },
            }
        },

        PcktState::Frag { mut need, mut part, seq, lst } => {
            if need == 0 && part.len() == 4 {
                need = mysql_packet_length(&part[..]);
            }
            let (used, need, pyld) = mysql_frag(need, bs);
            part.extend_from_slice(pyld);
            if need == 0 && part.len() > 4 {
                let (nxt, out) = state_act(c2s, seq, lst, &part[4..]);
                (used, PcktState::Start { lst: nxt, }, out)
            } else {
                (used, PcktState::Frag { need: need, part: part, seq: seq, lst: lst }, None)
            }
        },

    }
}

fn tcp_pyld(c2s: bool, strm: u16, bs: &[u8]) {
    debug!("tcp_pyld() in: c2s={:?}, strm={:?}, bs={:?}", c2s, strm, mk_ascii(bs));

    if bs.len() == 0 {
        // ignore empty packets
        return;
    }

    STATES.with(|rc| { let mut hm = rc.borrow_mut(); OUT.with(|f| { let mut cap = f.borrow_mut();
        let mut i: usize = 0;
        let mut st = match hm.get(&strm) {
            Some(mss) => mss.clone(),
            None => if c2s { PcktState::Start { lst: MySQLState::Wait, } } else { return; },
        };
        debug!("tcp_pyld() in: loop begin, c2s={:?}, strm={:?}", c2s, strm);
        while i < bs.len() {
            let (used, nxt, out) = nxt_state(c2s, st, &bs[i..]);
            debug!("nxt_state() out: strm={:?}, used={:?}, nxt={:?}, out={:?}", strm, used, nxt, out);
            i += used;
            st = nxt;
            if out.is_some() {
                let timespec = time::get_time();
                let millis = timespec.sec * 1000 + timespec.nsec as i64 / 1000 / 1000;
                let msg = format!("--GIBBS\tTIMESTAMP: {}\tSTREAM: {}\t{};\n", millis, strm, out.unwrap());
                write_cap(&mut cap, &msg);
            }
        }
        debug!("tcp_pyld() out: loop end, c2s={:?}, strm={:?}, st={:?}", c2s, strm, st);
        assert!(i == bs.len());

        hm.insert(strm, st);  // ending state
    }); });
}

fn tcp_pckt(iname: &str, src: IpAddr, dst: IpAddr, packet: &[u8], opt: &COpts) {
    let udp = UdpPacket::new(packet);  // use UDP packet since parts we use in same place
    if let Some(udp) = udp {
        if src == opt.host && udp.get_source() == opt.port {  // server -> client
            tcp_pyld(false, udp.get_destination(), &packet[(packet[12] >> 4) as usize * 4..]);
        } else if dst == opt.host && udp.get_destination() == opt.port {  // client -> server
            tcp_pyld(true, udp.get_source(), &packet[(packet[12] >> 4) as usize * 4..]);
        }
    } else {
        debug!("[{}]: Malformed TCP Packet", iname);
    }
}

fn transport_layer(iname: &str, src: IpAddr, dst: IpAddr, proto: IpNextHeaderProtocol, pckt: &[u8], opt: &COpts) {
    match proto {
        IpNextHeaderProtocols::Tcp => tcp_pckt(iname, src, dst, pckt, opt),
        _ => {},
    }
}

fn ipv4_pckt(iname: &str, ether: &EthernetPacket, opt: &COpts) {
    let hdr = Ipv4Packet::new(ether.payload());
    if let Some(hdr) = hdr {
        transport_layer(iname,
                        IpAddr::V4(hdr.get_source()),
                        IpAddr::V4(hdr.get_destination()),
                        hdr.get_next_level_protocol(),
                        hdr.payload(),
                        opt);
    } else {
        debug!("[{}]: Malformed IPv4 Packet", iname);
    }
}

fn process_pckt(iname: &str, ether: &EthernetPacket, opt: &COpts) {
    match ether.get_ethertype() {
        EtherTypes::Ipv4 => ipv4_pckt(iname, ether, opt),
        _ => {},
    }
}

// provides a list of valid network interfaces, excluding any loopback interfaces
pub fn get_iface_names() -> Vec<String> {
    let valid_ifaces = get_network_interfaces()
        .into_iter();
    let mut iface_names: Vec<String> = Vec::new();
    for iface in valid_ifaces {
        if !iface.is_loopback() && iface.ips.is_some() {
            let mut ipv4 = false;
            for ip in iface.ips.unwrap() {
                ipv4 = ipv4 || match ip {
                    IpAddr::V4(_) => true,
                    _ => false
                };
            }
            if ipv4 {
                iface_names.push(iface.name);
            }
        }
    }
    iface_names
}

pub fn sniff(opt: COpts) {
    let name_cmp = |iface: &NetworkInterface| iface.name == opt.iface;
    let ifaces = get_network_interfaces();

    let iface = match ifaces.into_iter().filter(name_cmp).next() {
        Some(f) => f,
        None => {
            println!("didn't find the '{}' network interface", opt.iface);
            return;
        },
    };

    let (_, mut rx) = match datalink_channel(&iface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("failure opening datalink: {}", e),
    };

    let mut iter = rx.iter();
    while chk_cap() {
        match iter.next() {
            Ok(p) => process_pckt(&iface.name[..], &p, &opt),
            Err(e) => panic!("failure receiving packet: {}", e),
        }
    }
}
