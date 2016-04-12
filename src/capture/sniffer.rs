use ::OUT;
use util::COpts;

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
    Columns { seq: u8, cnt: u8, },
    Rows { seq: u8, cnt: u32, },
}

#[derive(Clone, Debug)]
enum PcktState {
    Start { lst: MySQLState, },
    Frag { need: usize, part: Vec<u8>, seq: u8, lst: MySQLState, },
}

fn state_act(c2s: bool, nxt_seq: u8, lst: MySQLState, pyld: &[u8]) -> (MySQLState, Option<String>) {
    let redact = regex!(r#"(?x)( (?P<p>[\s=\(\+-/\*]) (
                            '[^'\\]*((\\.|'')[^'\\]*)*' |
                            "[^"\\]*((\\.|"")[^"\\]*)*" |
                            [\.][\d]+ | [\d][\.\d]*
                        ) )"#);

    match lst {
        MySQLState::Wait => { debug!("MySQLState::Wait");
            if !c2s || nxt_seq != 0 || pyld[0] != 3 {
                (MySQLState::Wait, None)
            } else {
                let qry = &pyld[1..];
                let cr = redact.replace_all(&str::from_utf8(qry).unwrap(), "$p?");
                (MySQLState::Query { seq: nxt_seq, }, Some(format!("STATEMENT:\n{}", cr)))
            }
        },

        MySQLState::Query { seq, } => { debug!("MySQLState::Query {{ seq: {:?}, }}", seq);
            if c2s || nxt_seq != 1 {
                state_act(c2s, nxt_seq, MySQLState::Wait, pyld)
            } else {
                let cols = pyld[0];
                (MySQLState::Columns { seq: nxt_seq, cnt: cols, }, None)
            }
        },

        MySQLState::Columns { seq, cnt, }=> { debug!("MySQLState::Columns {{ seq: {:?}, cnt: {:?}, }}", seq, cnt);
            if c2s {
                state_act(c2s, nxt_seq, MySQLState::Wait, pyld)
            } else if nxt_seq < cnt + 1 {
                (MySQLState::Columns { seq: nxt_seq, cnt: cnt, }, None)
            } else {
                (MySQLState::Rows { seq: nxt_seq, cnt: 0, }, None)
            }
        },

        MySQLState::Rows { seq, cnt, } => { debug!("MySQLState::Rows {{ {:?}, {:?} }}", seq, cnt);
            if c2s {
                state_act(c2s, seq, MySQLState::Wait, pyld)
            } else if pyld[0] != 0xfe {
                (MySQLState::Rows { seq: nxt_seq, cnt: cnt + 1, }, None)
            } else {
                let flg0 = pyld[3];
                let flg1 = pyld[4];
                (MySQLState::Wait, Some(format!("ROW_COUNT: {}   QUERY_SLOW: {}   NO_INDEX_USED: {}   NO_GOOD_INDEX_USED: {}",
                                                cnt, flg1 & 0x08 != 0, flg0 & 0x20 != 0, flg0 & 0x10 != 0)))
            }
        },

    }
}

fn mysql_frag(need: usize, bs: &[u8]) -> (usize, usize, &[u8]) {
    let used = cmp::min(need, bs.len());
    let pyld = &bs[0..used];
    let need = need - used;

    (used, need, pyld)
}

fn mysql_next(bs: &[u8]) -> (usize, usize, u8, &[u8]) {
    let len: usize = (bs[0] as usize) + ((bs[1] as usize) << 8) + ((bs[2] as usize) << 16);
    let seq: u8 = bs[3];
    let used = cmp::min(4 + len, bs.len());
    let pyld = &bs[4..used];
    let need = len + 4 - used;

    (used, need, seq, pyld)
}

fn nxt_state(c2s: bool, st: PcktState, bs: &[u8]) -> (usize, PcktState, Option<String>) {
    match st {
        PcktState::Start { lst, } => { debug!("PcktState::Start {{ {:?} }}", lst);
            let (used, need, seq, pyld) = mysql_next(bs);
            if need == 0 {
                let (nxt, out) = state_act(c2s, seq, lst, pyld);
                (used, PcktState::Start { lst: nxt, }, out)
            } else {
                let mut v: Vec<u8> = Vec::new();
                v.extend_from_slice(pyld);
                (used, PcktState::Frag { need: need, part: v, seq: seq, lst: lst }, None)
            }
        },

        PcktState::Frag { need, mut part, seq, lst } => { debug!("PcktState::Frag {{ {:?}, {:?}, {:?}, {:?}, }}", need, part, seq, lst);
            let (used, need, pyld) = mysql_frag(need, bs);
            part.extend_from_slice(pyld);
            if need == 0 {
                let (nxt, out) = state_act(c2s, seq, lst, &part[..]);
                (used, PcktState::Start { lst: nxt, }, out)
            } else {
                (used, PcktState::Frag { need: need, part: part, seq: seq, lst: lst }, None)
            }
        },

    }
}

fn tcp_pyld(c2s: bool, strm: u16, bs: &[u8]) {
    debug!("tcp_pyld: c2s {:?}, strm {:?}, bs {:?}", c2s, bs, strm);

    STATES.with(|rc| { let mut hm = rc.borrow_mut(); OUT.with(|f| { let mut tmp = f.borrow_mut();
        let mut i: usize = 0;
        let mut st = match hm.get(&strm) {
            Some(mss) => mss.clone(),
            None => PcktState::Start { lst: MySQLState::Wait, },
        };
        while i < bs.len() {
            let (used, nxt, out) = nxt_state(c2s, st, &bs[i..]);
            i += used;
            st = nxt;
            if out.is_some() {
                let timespec = time::get_time();
                let millis = timespec.sec * 1000 + timespec.nsec as i64 / 1000 / 1000;
                let _ = writeln!(tmp, "{}", format!("-- TIMESTAMP: {}   STREAM: {}   {};", millis, strm, out.unwrap()));
            }
        }
        assert!(i == bs.len());

        hm.insert(strm, st);  // ending state
    }); });
}

fn tcp_pckt(iname: &str, source: IpAddr, destination: IpAddr, packet: &[u8], opt: &COpts) {
    let udp = UdpPacket::new(packet);  // use UDP packet since parts we use in same place
    if let Some(udp) = udp {
        if source == opt.host && udp.get_source() == opt.port {  // server -> client
            tcp_pyld(false, udp.get_destination(), &packet[(packet[12] >> 4) as usize * 4..]);
        } else if destination == opt.host && udp.get_destination() == opt.port {  // client -> server
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

pub fn sniff(opt: COpts) {
    let name_cmp = |iface: &NetworkInterface| iface.name == opt.iface;
    let ifaces = get_network_interfaces();
    let iface = ifaces.into_iter().filter(name_cmp).next().unwrap();

    let (_, mut rx) = match datalink_channel(&iface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("failure opening datalink: {}", e),
    };

    let mut iter = rx.iter();
    loop {
        match iter.next() {
            Ok(p) => process_pckt(&iface.name[..], &p, &opt),
            Err(e) => panic!("failure receiving packet: {}", e)
        }
    }
}
