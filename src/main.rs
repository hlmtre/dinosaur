mod config;
mod server;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
  env,
  ffi::CString,
  net::{IpAddr, Ipv4Addr, SocketAddr},
};

fn main() {
  let c = config::Config::default();
  let socket = match Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())) {
    Ok(a) => a,
    _ => panic!("couldn't create socket :("),
  };
  if !c.interface.is_empty() {
    socket
      .bind_device(Some(&CString::new(c.interface.clone()).unwrap()))
      .unwrap_or_else(|_| panic!("couldn't bind to {}", c.interface));
  }
  socket
    .bind(&c.ip_address.into())
    .unwrap_or_else(|_| panic!("couldn't bind to {}", c.ip_address));
  server::service_loop(socket, c);
}
