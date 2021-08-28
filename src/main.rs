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
  if c.interface.clone().len() > 0 {
    socket
      .bind_device(Some(&CString::new(c.interface.clone()).unwrap()))
      .expect(format!("couldn't bind to {}", c.interface).as_str());
  }
  socket
    .bind(&c.ip_address.into())
    .expect(format!("couldn't bind to {}", c.ip_address).as_str());
  server::service_loop(socket, c);
}
