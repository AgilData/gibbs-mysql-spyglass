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

extern crate mysql;

use self::mysql::*;
use std::default::Default;

use ::util::COpts;

use time;

use ::OUT;

use std::io::Write;

pub fn schema(opt: COpts) {
    let db = opt.db.clone().into_boxed_str();
    let my_opts = Opts {
        ip_or_hostname: Some(opt.host.to_string()),
        tcp_port: opt.port,
        user: Some(opt.user),
        pass: Some(opt.pass),
        db_name: Some(opt.db),
        ..Default::default()
    };
    let pool = mysql::Pool::new(my_opts).unwrap();

    let tables: Vec<String> = pool
        .prep_exec("show tables", ())
        .map(|result| { result
            .map(|x| x.unwrap())
            .map(|row| {
                let (name, ) = mysql::from_row(row);
                name
            })
            .collect()
        })
        .unwrap();

    OUT.with(|f| {
        let mut tmp = f.borrow_mut();

        for t in tables {
            let timespec = time::get_time();
            let millis = timespec.sec * 1000 + timespec.nsec as i64 / 1000 / 1000;
            let _ = pool.prep_exec(format!("show create table {}", t), ())
                        .map(|res| { res
                            .map(|x| x.unwrap())
                            .fold((), |_, row| {
                                let (_, c,): (String, String) = mysql::from_row(row);
                                let _ = writeln!(tmp, "--GIBBS\tTYPE: DDL\tTIMESTAMP: {}\tSCHEMA: {}\tSQL:\n{};", millis, db, c);
                                printfl!(".");
                            })
                        });

            let _ = pool.prep_exec(format!("SELECT table_rows, data_length, index_length FROM information_schema.tables WHERE table_schema = '{}' AND table_name = '{}'", db, t), ())
                        .map(|res| { res
                            .map(|x| x.unwrap())
                            .fold((), |_, row| {
                                let (row_count,data_length,index_length): (u64,u64,u64) = mysql::from_row(row);
                                let _ = writeln!(tmp,
                                    "--GIBBS\tTYPE: TABLE_STATS\tTIMESTAMP: {}\tTABLE: {}\tROW_COUNT: {}\tDATA_LENGTH: {}\tINDEX_LENGTH: {};",
                                    millis, t, row_count, data_length, index_length);
                                printfl!(".");
                            })
                        });

        }

    });
}
