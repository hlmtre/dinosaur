use crate::config::Config;
use socket2::{Domain, Protocol, Socket, Type};
pub(crate) fn service_loop(s: Socket, c: Config) {
  eprintln!("{:?}", s);
  eprintln!("{:?}", c);
  let mut counter: usize = 0;
  loop {
    if counter > 100 {
      break;
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
    counter += 1;
  }
  return;
}
