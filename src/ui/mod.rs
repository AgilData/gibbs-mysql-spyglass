use std::str;

pub fn index() -> &'static str {
    str::from_utf8(include_bytes!("index.html")).unwrap()
}
