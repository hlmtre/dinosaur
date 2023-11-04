use crate::dnserror::DnsError;
use std::{
  fs::File,
  io::{BufRead, BufReader, Error, Read},
  net::{SocketAddr, SocketAddrV4},
  path::Path,
  path::PathBuf,
};

#[derive(Debug)]
pub(crate) struct Config {
  pub interface: String,
  pub ip_address: SocketAddrV4,
  pub config_location: PathBuf,
}

impl Config {
  pub(crate) fn default() -> Result<Config, DnsError> {
    Ok(Config {
      interface: "du0".to_string(),
      ip_address: "0.0.0.0:5354".parse::<std::net::SocketAddrV4>().unwrap(),
      config_location: Path::new(".").to_owned(),
    })
  }
  pub(crate) fn load(f: String) -> std::io::Result<Config> {
    let mut config = Self::default().unwrap();
    let path = PathBuf::from(f.clone());
    let file = File::open(&path)?;
    let buf_reader = BufReader::new(file);
    for line in buf_reader.lines() {
      match line {
        Ok(l) => {
          if l.starts_with("interface") {
            let line_elements: Vec<_> = l.split(' ').collect();
            config.interface = line_elements
              .last()
              .unwrap()
              .trim()
              .replace('\"', "")
              .to_string();
          }
          if l.starts_with("ip_address") {
            let line_elements: Vec<_> = l.split(' ').collect();
            // we get something like "\"172.16.35.1:5354\"" so we have to strip the double quote
            // characters here (and .trim() removes newlines)
            let ip = line_elements.last().unwrap().trim().replace('\"', "");
            config.ip_address = match ip.parse::<std::net::SocketAddrV4>() {
              Ok(i) => i,
              Err(e) => {
                eprintln!(
                  "error parsing socket address! using default... error:{:#?}",
                  e
                );
                "0.0.0.0:5354".parse::<std::net::SocketAddrV4>().unwrap()
              }
            }
          }
        }
        Err(_) => todo!(),
      }
    }
    config.config_location = std::fs::canonicalize(path).unwrap();
    Ok(config)
  }
}
