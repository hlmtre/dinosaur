use crate::config::Config;
use crate::dnsmessage;
use socket2::{Domain, Protocol, Socket, Type};
pub(crate) fn service_loop(s: Socket, c: Config) -> std::io::Result<()> {
  eprintln!("listening for dns requests...");
  eprintln!("{:?}", s);
  eprintln!("{:?}", c);
  let mut buf = [0_u8; 576];
  #[allow(unreachable_code)]
  loop {
    let a = match s.recv_from(&mut buf) {
      Ok(b) => b,
      Err(_) => todo!(),
    };
    let mut message = dnsmessage::DnsMessage::default();
    eprintln!("{:#?}", message);
    match message.parse(&buf) {
      Ok(m) => {
        eprintln!(
          "received {:#?} bytes from socket from client {:#?}",
          a.0, a.1
        );
        println!("{}", message);
        eprintln!("bytes: {:x?}", &buf);
      }
      Err(e) => eprintln!("{:x?}", e),
    };
  }
  #[allow(unreachable_code)]
  Ok(())
}
