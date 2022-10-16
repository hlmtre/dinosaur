use crate::dnserror::DnsError;
use std::fmt;

#[derive(Debug, Default)]
pub(crate) struct DnsMessage {
  pub(crate) tx_id: u16,
  pub(crate) flags: u16,
  pub(crate) questions: u16,
  pub(crate) answer_rrs: u16,
  pub(crate) authority_rrs: u16,
  pub(crate) additional_rrs: u16,
  pub(crate) queries: Vec<u8>,
}

//pub(crate) fn parse(&mut self, buf: &[u8]) {
//self.secs = u16::from_be_bytes(buf[8..10].try_into().unwrap());
//
impl fmt::Display for DnsMessage {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "DnsMessage tx_id: {:x?}, flags: {:x?}",
      self.tx_id, self.flags
    )
  }
}

impl DnsMessage {
  pub(crate) fn parse(&mut self, buf: &[u8]) -> Result<(), DnsError> {
    self.tx_id = u16::from_be_bytes(buf[0..2].try_into()?);
    self.flags = u16::from_be_bytes(buf[3..5].try_into()?);
    Ok(())
  }
}
