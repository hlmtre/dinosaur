use crate::{config::Config, dnsmessage::DnsMessage};
use socket2::{Domain, Protocol, Socket, Type};

pub(crate) fn service_loop(s: Socket, c: Config) -> std::io::Result<()> {
  eprintln!("listening for dns requests...");
  eprintln!("{:?}", s);
  eprintln!("{:?}", c);
  let mut buf = [0_u8; 512]; // maximum non-eDNS len
  #[allow(unreachable_code)]
  loop {
    let a = match s.recv_from(&mut buf) {
      Ok(b) => b,
      Err(_) => todo!(),
    };
    let mut message: DnsMessage = DnsMessage::default();
    match message.parse(&buf) {
      Ok(_m) => {
        eprintln!(
          "received {:#?} bytes from socket from client {:#?}",
          a.0, a.1
        );
        println!("{}", message);
        eprintln!("bytes: {:02x?}", &buf);
      }
      Err(e) => eprintln!("{:02x?}", e),
    };
  }
  #[allow(unreachable_code)]
  Ok(())
}
