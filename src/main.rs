#![feature(plugin)]
#![plugin(regex_macros)]

#[macro_use]
extern crate log;
extern crate log4rs;

extern crate hyper;

#[macro_use]
extern crate nickel;
use nickel::Nickel;

extern crate argparse;
use argparse::{ArgumentParser, Store};

extern crate rand;

extern crate time;

extern crate regex;

use std::thread;

mod util;
use util::{COpts, TMP_FILE};
use std::net::{IpAddr, Ipv4Addr};

mod ui;

mod capture;
use capture::client::schema;
use capture::sniffer::sniff;

mod comm;
use comm::upload;

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};

thread_local!(static OUT: RefCell<File> =
    RefCell::new(OpenOptions::new().read(true).append(true).create(true).open(TMP_FILE).unwrap())
);

fn main() {
    let _ = fs::remove_file(TMP_FILE);
    let _ = log4rs::init_file("gibbs.toml", Default::default());

    let mut opt = COpts {
        pin: (rand::random::<u32>() % 10_000_000),
        host: IpAddr::V4(Ipv4Addr::new(0,0,0,0)),
        port: 3306,
        user: "root".to_string(),
        pass: "".to_string(),
        db: "".to_string(),
        iface: "".to_string(),
    };

    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Analyze your MySQL server traffic and configuration (must be run using sudo)");
        ap.refer(&mut opt.host)
            .required()
            .add_option(&["--host"], Store,
            "IP address of MySQL server");
        ap.refer(&mut opt.port)
            .add_option(&["--port"], Store,
            "Number of the MySQL port");
        ap.refer(&mut opt.user)
            .add_option(&["--user"], Store,
            "MySQL username");
        ap.refer(&mut opt.pass)
            .required()
            .add_option(&["--pass"], Store,
            "MySQL password");
        ap.refer(&mut opt.db)
            .required()
            .add_option(&["--db"], Store,
            "MySQL database");
        ap.refer(&mut opt.iface)
            .required()
            .add_option(&["--iface"], Store,
            "Network interface");
        ap.parse_args_or_exit();
    }
    // debug!("AgilData MySQL Analyzer started with {:?}", opt);
    debug!("generated Access PIN: {:06}", opt.pin);

    let mut httpd = Nickel::new();
    httpd.utilize(router! {
        get "/" => |_req, _res| {
            ui::index()
        }

        post "/capture" => |_req, _res| {
            {
                let schema_opt = opt.clone();
                schema(schema_opt);
            }
            {
                let sniff_opt = opt.clone();
                thread::spawn(|| {
                    sniff(sniff_opt);
                });
            }

            "Data Capture Started!\n"
        }

        post "/upload" => |_req, _res| {
            upload();

            "Data Uploaded!\n"
        }

    });

    httpd.listen("0.0.0.0:3333");

}
