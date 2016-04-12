use util::{TMP_FILE, VERSION};

use hyper;

extern crate multipart;
use self::multipart::client::Multipart;

use std::fs::File;

pub fn upload() {
    debug!("STARTING MULTIPART UPLOAD");
    use hyper::header::{Authorization, Basic, UserAgent};

    let mut req = hyper::client::request::Request::new(
        hyper::method::Method::Post,
        hyper::Url::parse("http://mysql-analyzer.agildata.com/api/analyses").unwrap()
    ).unwrap();
    {
        let hdrs = req.headers_mut();
        hdrs.set(Authorization(Basic {
            username: "97947bf70fecdba64c33574ad5c1c1a365bd0c30".to_owned(),
            password: None, }));
        hdrs.set(UserAgent(format!("AgilData/gibbs-mysql-spyglass/{}", VERSION).to_owned()));
    }

    let mut mp = { Multipart::from_request(req).unwrap() };
    let f: &mut File = &mut File::open(TMP_FILE).unwrap();
    let _ = mp.write_stream("submission", f, Some(TMP_FILE), None).unwrap();
    let res = mp.send();

    debug!("MULTIPART returned {:?}", res);
}
