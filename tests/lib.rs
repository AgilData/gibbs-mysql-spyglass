#[macro_use]
extern crate log;
extern crate log4rs;

// extern crate mysql;
//
// use self::mysql::*;


#[cfg(test)]
mod tests {

    #[test]
    fn test_300_columns() {
        init_schema();
    }

    fn init_schema() {
        let mut ddl = String::from("CREATE TABLE gibbs_test (");
        for c in 1..300 {
            if c > 1 { ddl.push_str(",\n"); }
            ddl.push_str(&c.to_string());
            ddl.push_str(" INTEGER NOT NULL");
        }
        ddl.push_str(")");
        debug!("DDL: {:?}", ddl);
    }

    // fn connect() -> mysql::Pool {
    //     let db = opt.db.clone().into_boxed_str();
    //     let my_opts = Opts {
    //         ip_or_hostname: Some(String::from("1.2.3.4")),
    //         tcp_port: 3306,
    //         user: Some(String::from("user")),
    //         pass: Some(String::from("pass")),
    //         db_name: Some(String::from("db")),
    //         ..Default::default()
    //     };
    //     let pool = mysql::Pool::new(my_opts).unwrap();
    // }
}
