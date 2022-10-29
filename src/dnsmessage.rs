use crate::dnserror::DnsError;

use bitlab::*;
use std::convert::TryInto;
use std::fmt;

const HEADER_LEN: u8 = 12;

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
  pub(crate) raw_flags: u16,
  pub(crate) questions: u16,
  pub(crate) answer_rrs: u16,
  pub(crate) authority_rrs: u16,
  pub(crate) additional_rrs: u16,
  pub(crate) host: String,
  flags: Flags,
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

/*
impl TryFrom<u16> for DnsMessageType {
  type Error = ();

  fn try_from(v: u16) -> Result<Self, Self::Error> {
    match v {
      x if x == DnsMessageType::Query as u16 => Ok(DnsMessageType::Query),
      x if x == DnsMessageType::Response as u16 => Ok(DnsMessageType::Response),
      _ => Err(()),
    }
  }
}
*/

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

/*
    0... .... .... .... = Response: Message is a query
    .000 0... .... .... = Opcode: Standard query (0)
    .... ..0. .... .... = Truncated: Message is not truncated
    .... ...1 .... .... = Recursion desired: Do query recursively
    .... .... .0.. .... = Z: reserved (0)
    .... .... ..1. .... = AD bit: Set
    .... .... ...0 .... = Non-authenticated data: Unacceptable

    0000 0001 0010 0000 = 0x0120
    .000 0... .... .... = Opcode: Standard query (0)
    .010 0 would be dec 4, and would be an inverse request
*/
impl Flags {
  fn new(raw_flags: u16) -> Self {
    Flags {
      rq: if !raw_flags.get_bit(1).unwrap() {
        DnsMessageType::Query
      } else {
        DnsMessageType::Response
      },
      query_type: if raw_flags.get_bit(2).unwrap() {
        QueryType::Inverse
      } else {
        QueryType::Standard
      },
      authoritative: true,
      truncated: false,
      recursive: true,
      recursion_available: true,
      authenticated: false,
      error: DnsResponseErrorType::NoError,
    }
  }
}

impl fmt::Display for Flags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      r#"Flags: 
            {}, 
            {} 
            authoritative: {} 
            truncated: {} 
            recursive: {} 
            recursion_available: {} 
            authenticated: {} 
            {}"#,
      self.rq,
      self.query_type,
      self.authoritative,
      self.truncated,
      self.recursive,
      self.recursion_available,
      self.authenticated,
      self.error
    )
  }
}

impl fmt::Display for DnsMessage {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      r#"DnsMessage tx_id: == {:02x} ==
      flags: {} 
      questions: {:02x}, answer_rrs: {:02x}
      host: {:?}
      "#,
      self.tx_id, self.flags, self.questions, self.answer_rrs, self.host
    )
  }
}

impl DnsMessage {
  pub(crate) fn parse(&mut self, buf: &[u8]) -> Result<(), DnsError> {
    self.tx_id = u16::from_be_bytes(buf[0..2].try_into()?);
    self.raw_flags = u16::from_be_bytes(buf[2..4].try_into()?);
    // multiple questions basically not supported by any dns server
    // https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071
    // self.questions = 1;
    self.questions = u16::from_be_bytes(buf[4..6].try_into()?);
    self.answer_rrs = u16::from_be_bytes(buf[6..8].try_into()?);
    self.authority_rrs = u16::from_be_bytes(buf[8..10].try_into()?);
    self.additional_rrs = u16::from_be_bytes(buf[10..12].try_into()?);
    // the header's 12 bytes long
    // now we're at query
    // first we're going to be told how long the first unicode string is,
    // then the first part of the host name,
    // then the length of the next chunk, then the next part of the host name..
    // ad infinitum, not quite
    /*
            *                     query name              type   class
              -----------------------------------  -----  -----
       HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
       ASCII     g  o  o  g  l  e     c  o  m
       DEC    6                    3           0       1      1
       thanks https://github.com/EmilHernvall/dnsguide/blob/master/chapter1.md for the chart
    */
    let mut index = usize::from(HEADER_LEN);
    let mut host_chunk_len = buf[index];
    // we have to step through one name chunk at a time
    //   g o o g l e   c o m
    // 6             3       0
    // ^ here
    //               ^ then here
    //                       ^ then here, and discover we're done
    let mut temp_host = String::new();
    while host_chunk_len != 0 {
      temp_host.push_str(
        String::from_utf8(self.take_next(buf, &mut index, host_chunk_len.into())?)
          .unwrap()
          .as_str(),
      );
      host_chunk_len = buf[index];
      temp_host.push('.');
    }
    self.flags = Flags::new(self.raw_flags);
    self.host = self.remove_dot(temp_host);
    Ok(())
  }

  fn remove_dot(&self, value: String) -> String {
    let mut chars = value.chars();
    chars.next_back();
    chars.as_str().to_string()
  }

  /*
    hop along the byte array, grabbing chunks, and then incrementing our index, so the next call grabs the next specified length
    and can increment the index to the start of the following one
  */
  fn take_next(
    &self,
    buf: &[u8],
    current_index: &mut usize,
    jump: usize,
  ) -> Result<Vec<u8>, DnsError> {
    // here we do have to get the NEXT one,
    // because the current_index is just the position of the length of characters to read
    /*
        ... 0 1 2 3 4 5 6 7 8 9 a
        ... 6[g o o g l e]3 c o m
                          ^
      update current index to len of next chunk
    */
    *current_index += 1;
    let ret = buf[*current_index..*current_index + jump].to_vec();
    *current_index += jump;
    Ok(ret)
  }
}
