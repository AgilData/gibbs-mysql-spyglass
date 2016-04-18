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

use util::COpts;
use capture::CAP_FILE;
use hyper;

extern crate multipart;
use self::multipart::client::Multipart;

use std::fs::File;

pub fn upload(opt: COpts) -> bool {
    debug!("STARTING MULTIPART UPLOAD");
    use hyper::header::{Authorization, Basic, UserAgent};

    let mut req = match hyper::client::request::Request::new(
                            hyper::method::Method::Post,
                            hyper::Url::parse("https://gibbs.agildata.com/api/analyses").unwrap()
                        ) {
                            Ok(o) => o,
                            Err(e) => { debug!("upload() fail: request={:?}", e); return false },
                        };

    {
        let hdrs = req.headers_mut();
        hdrs.set(Authorization(Basic {
            username: opt.key,
            password: None, }));
        hdrs.set(UserAgent(format!("AgilData/gibbs-mysql-spyglass/{}", ::VERSION).to_owned()));
    }

    let mut mp = { match Multipart::from_request(req) {
                            Ok(o) => o,
                            Err(e) => { debug!("upload() fail: multipart={:?}", e); return false },
                         }
                 };
    let f = &mut match File::open(CAP_FILE) {
                           Ok(o) => o,
                           Err(e) => { debug!("upload() fail: file={:?}", e); return false },
                       };
    let _ = mp.write_stream("submission", f, Some(CAP_FILE), None);
    match mp.send() {
        Ok(_) => true,
        Err(e) => { debug!("upload() fail: send={:?}", e); return false },
    }
}
