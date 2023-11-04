mod config;
mod dnserror;
mod dnsmessage;
mod server;
use config::Config;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
  env,
  ffi::CString,
  net::{IpAddr, Ipv4Addr, SocketAddr},
};

fn main() {
  let args: Vec<String> = env::args().collect();
  // so we can get the next arg AFTER our flag
  /*
  if args.len() < 2 {
    help();
    std::process::exit(1);
  }
  */
  for e in &args {
    if e == "-h" || e == "--help" {
      help();
      std::process::exit(0);
    }
  }
  let cr = config::Config::load("config".to_string());
  let socket = match Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())) {
    Ok(a) => a,
    _ => panic!("couldn't create socket :("),
  };
  match cr {
    Ok(c) => {
      if !c.interface.is_empty() {
        socket
          .bind_device(Some(&CString::new(c.interface.clone()).unwrap()))
          .unwrap_or_else(|_| panic!("couldn't bind to {}", c.interface));
      }
      socket
        .bind(&c.ip_address.into())
        .unwrap_or_else(|_| panic!("couldn't bind to {}", c.ip_address));
      if server::service_loop(socket, c).is_ok() {
        std::process::exit(0)
      } else {
        std::process::exit(1)
      };
    }
    Err(e) => {
      eprintln!("error! {:?}", e);
      std::process::exit(1);
    }
  }
}

fn help() {
  println!("dnsrs --upstream <upstream resolver> --interface <interface to bind to> --port <port>");
  std::process::exit(0);
}
