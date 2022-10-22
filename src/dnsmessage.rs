use crate::dnserror::DnsError;
use bitflags::bitflags;
use std::fmt;

/*
*
   Domain Name System (query)
       Transaction ID: 0x163f
       Flags: 0x0120 Standard query
           0... .... .... .... = Response: Message is a query
           .000 0... .... .... = Opcode: Standard query (0)
           .... ..0. .... .... = Truncated: Message is not truncated
           .... ...1 .... .... = Recursion desired: Do query recursively
           .... .... .0.. .... = Z: reserved (0)
           .... .... ..1. .... = AD bit: Set
           .... .... ...0 .... = Non-authenticated data: Unacceptable
       Questions: 1
       Answer RRs: 0
       Authority RRs: 0
       Additional RRs: 1
       Queries
           google.com: type A, class IN
               Name: google.com
               [Name Length: 10]
               [Label Count: 2]
               Type: A (Host Address) (1)
               Class: IN (0x0001)
       Additional records
           <Root>: type OPT
               Name: <Root>
               Type: OPT (41)
               UDP payload size: 4096
               Higher bits in extended RCODE: 0x00
               EDNS0 version: 0
               Z: 0x0000
                   0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                   .000 0000 0000 0000 = Reserved: 0x0000
               Data length: 12
               Option: COOKIE

*/

#[derive(Debug, Default)]
pub(crate) struct DnsMessage {
  pub(crate) tx_id: u16,
  pub(crate) flags: u16,
  pub(crate) questions: u16,
  pub(crate) answer_rrs: u16,
  pub(crate) authority_rrs: u16,
  pub(crate) additional_rrs: u16,
  pub(crate) queries: Vec<u8>,
  Flags: Flags,
}
/*
    Flags: 0x0120 Standard query
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..1. .... = AD bit: Set
        .... .... ...0 .... = Non-authenticated data: Unacceptable

*/
#[derive(Debug)]
pub(crate) enum DnsResponseErrorType {
  NoError = 0,
  NXRecord = 1,
  ServerFailure = 2,
  FormatError = 4,
}

impl fmt::Display for DnsResponseErrorType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "DnsResponseErrorType: {:?}", self)
  }
}

#[derive(Debug)]
pub(crate) enum DnsMessageType {
  Query = 0,
  Response,
}

impl fmt::Display for DnsMessageType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "DnsMessageType: {:?}", self)
  }
}

#[derive(Debug)]
pub(crate) enum QueryType {
  Standard = 0,
  Inverse = 4, // in-addr.arpa
}

impl fmt::Display for QueryType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "QueryType: {:?}", self)
  }
}

#[derive(Debug)]
pub(crate) struct Flags {
  rq: DnsMessageType,
  query_type: QueryType,
  authoritative: bool,
  truncated: bool,
  recursive: bool,
  recursion_available: bool,
  authenticated: bool,
  error: DnsResponseErrorType,
}

impl Default for Flags {
  fn default() -> Flags {
    Flags {
      rq: DnsMessageType::Query,
      query_type: QueryType::Standard,
      authoritative: false,
      truncated: false,
      recursive: false,
      recursion_available: false,
      authenticated: false,
      error: DnsResponseErrorType::NoError,
    }
  }
}

impl fmt::Display for Flags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Flags: {}, query_type: {}, authoritative {}, truncated: {}, recursive: {}, recursion_available: {}, authenticated: {}, error: {}", self.rq, self.query_type, self.authoritative, self.truncated, self.recursive, self.recursion_available, self.authenticated, self.error)
  }
}

//pub(crate) fn parse(&mut self, buf: &[u8]) {
//self.secs = u16::from_be_bytes(buf[8..10].try_into().unwrap());
//
impl fmt::Display for DnsMessage {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "DnsMessage tx_id: {:02x}, flags: {:02x}, questions: {:02x}, answer_rrs: {:02x}",
      self.tx_id, self.flags, self.questions, self.answer_rrs
    );
    write!(f, "flaggy: {}", self.flags << 1)
  }
}

impl DnsMessage {
  pub(crate) fn parse(&mut self, buf: &[u8]) -> Result<(), DnsError> {
    self.tx_id = u16::from_be_bytes(buf[0..2].try_into()?);
    self.flags = u16::from_be_bytes(buf[3..5].try_into()?);
    self.questions = u16::from_be_bytes(buf[6..8].try_into()?);
    self.answer_rrs = u16::from_be_bytes(buf[9..11].try_into()?);
    self.authority_rrs = u16::from_be_bytes(buf[12..14].try_into()?);
    self.additional_rrs = u16::from_be_bytes(buf[15..17].try_into()?);
    Ok(())
  }

  fn take_next(
    &self,
    buf: &[u8],
    current_index: &mut usize,
    jump: usize,
  ) -> Result<Vec<u8>, DnsError> {
    let ret = buf[*current_index..*current_index + jump].to_vec();
    *current_index += jump;
    Ok(ret)
  }
}
