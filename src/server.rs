use crate::{
  config::Config,
  dnsmessage::{DnsMessage, DnsRecord, PacketBuf},
};
use socket2::{Domain, Protocol, Socket, Type};

pub(crate) fn service_loop(s: Socket, c: Config) -> std::io::Result<()> {
  eprintln!("listening for dns requests...");
  eprintln!("{:?}", s);
  eprintln!("{:?}", c);
  let mut pktbuf = PacketBuf::new();
  #[allow(unreachable_code)]
  loop {
    let a = match s.recv_from(&mut pktbuf.buf) {
      Ok(b) => b,
      Err(_) => todo!(),
    };
    let mut message: DnsMessage = DnsMessage::default();
    /*
    for b in buf {
      print!("{:016b} ", b);
    }
    */
    println!();
    match message.parse(&pktbuf.buf) {
      Ok(mut _m) => {
        eprintln!(
          "received {:#?} bytes from socket from client {:#?}",
          a.0, a.1
        );
        //println!("{:?}", _m);
        // TODO
        // respond to the message here
        println!("query: {:02x?}", &_m);
        let r = _m.generate_response();
        let _x = r.unwrap().to_owned();
        println!("response: {:02x?}", _x);
      }
      Err(e) => eprintln!("{:02x?}", e),
    };
  }
  #[allow(unreachable_code)]
  Ok(())
}
