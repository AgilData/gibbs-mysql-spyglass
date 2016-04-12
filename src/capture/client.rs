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
                                let _ = writeln!(tmp, "-- TIMESTAMP: {}   SCHEMA: {}   STATEMENT:\n{};", millis, db, c);
                            })
                        });

            let _ = pool.prep_exec(format!("select table_rows from information_schema.tables where table_name = '{}'", t), ())
                        .map(|res| { res
                            .map(|x| x.unwrap())
                            .fold((), |_, row| {
                                let (c,): (u64,) = mysql::from_row(row);
                                let _ = writeln!(tmp, "-- TIMESTAMP: {}   TABLE: {}   ROW_COUNT: {};", millis, t, c);
                            })
                        });
        }
    });
}
