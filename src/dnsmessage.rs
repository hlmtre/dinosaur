use crate::dnserror::DnsError;
use std::net::Ipv4Addr;

//use bitlab::*;
use std::convert::TryInto;
use std::fmt;

//type Error = Box<dyn std::error::Error>;
//type Result<T> = std::result::Result<T, Error>;

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


    Domain Name System (response)
        Transaction ID: 0x20f8
        Flags: 0x8180 Standard query response, No error
            1... .... .... .... = Response: Message is a response
            .000 0... .... .... = Opcode: Standard query (0)
            .... .0.. .... .... = Authoritative: Server is not an authority for domain
            .... ..0. .... .... = Truncated: Message is not truncated
            .... ...1 .... .... = Recursion desired: Do query recursively
            .... .... 1... .... = Recursion available: Server can do recursive queries
            .... .... .0.. .... = Z: reserved (0)
            .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
            .... .... ...0 .... = Non-authenticated data: Unacceptable
            .... .... .... 0000 = Reply code: No error (0)
        Questions: 1
        Answer RRs: 1
        Authority RRs: 0
        Additional RRs: 1
        Queries
            chea-dfs.ad.nvih.org: type A, class IN
                Name: chea-dfs.ad.nvih.org
                [Name Length: 20]
                [Label Count: 4]
                Type: A (Host Address) (1)
                Class: IN (0x0001)
        Answers
            chea-dfs.ad.nvih.org: type A, class IN, addr 10.148.76.5
                Name: chea-dfs.ad.nvih.org
                Type: A (Host Address) (1)
                Class: IN (0x0001)
                Time to live: 1200 (20 minutes)
                Data length: 4
                Address: 10.148.76.5
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
                Data length: 0

*/

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub(crate) enum DnsRecord {
  UNKNOWN {
    domain: String,
    qtype: u16,
    data_len: u16,
    ttl: u32,
  }, // 0
  A {
    domain: String,
    addr: Ipv4Addr,
    ttl: u32,
  }, // 1
}

impl DnsRecord {
  pub fn read(buffer: &mut PacketBuf) -> Result<DnsRecord, DnsError> {
    let mut domain = String::new();
    buffer.read_qname(&mut domain)?;

    println!("{}", domain);
    let qtype_num = buffer.read_u16()?;
    let qtype = QueryType::from_num(qtype_num);
    let _ = buffer.read_u16()?;
    let ttl = buffer.read_u32()?;
    let data_len = buffer.read_u16()?;

    match qtype {
      QueryType::A => {
        let raw_addr = buffer.read_u32()?;
        let addr = Ipv4Addr::new(
          ((raw_addr >> 24) & 0xFF) as u8,
          ((raw_addr >> 16) & 0xFF) as u8,
          ((raw_addr >> 8) & 0xFF) as u8,
          ((raw_addr >> 0) & 0xFF) as u8,
        );

        Ok(DnsRecord::A { domain, addr, ttl })
      }
      QueryType::UNKNOWN(_) => {
        buffer.step(data_len as usize);

        Ok(DnsRecord::UNKNOWN {
          domain,
          qtype: qtype_num,
          data_len,
          ttl,
        })
      }
    }
  }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5,
}

impl ResultCode {
  pub fn from_num(num: u8) -> ResultCode {
    match num {
      1 => ResultCode::FORMERR,
      2 => ResultCode::SERVFAIL,
      3 => ResultCode::NXDOMAIN,
      4 => ResultCode::NOTIMP,
      5 => ResultCode::REFUSED,
      0 | _ => ResultCode::NOERROR,
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct DnsMessage {
  pub(crate) tx_id: u16,
  pub(crate) raw_flags: u16,
  pub(crate) questions: u16,
  pub(crate) answers: u16,
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
pub(crate) enum MessageType {
  Standard = 0,
  Inverse = 4, // in-addr.arpa
}

impl fmt::Display for MessageType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "QueryType: {:?}", self)
  }
}

#[derive(Debug)]
pub(crate) struct Flags {
  rq: DnsMessageType,
  query_type: MessageType,
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
      query_type: MessageType::Standard,
      authoritative: false,
      truncated: false,
      recursive: false,
      recursion_available: false,
      authenticated: false,
      error: DnsResponseErrorType::NoError,
    }
  }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
  UNKNOWN(u16),
  A, // 1
}

impl QueryType {
  pub fn to_num(&self) -> u16 {
    match *self {
      QueryType::UNKNOWN(x) => x,
      QueryType::A => 1,
    }
  }

  pub fn from_num(num: u16) -> QueryType {
    match num {
      1 => QueryType::A,
      _ => QueryType::UNKNOWN(num),
    }
  }
}

#[derive(Debug)]
pub(crate) struct PacketBuf {
  pub buf: [u8; 512],
  pub pos: usize,
}

impl PacketBuf {
  /// This gives us a fresh buffer for holding the packet contents, and a
  /// field for keeping track of where we are.
  pub fn new() -> PacketBuf {
    PacketBuf {
      buf: [0; 512],
      pos: 0,
    }
  }

  /// Current position within buffer
  fn pos(&self) -> usize {
    self.pos
  }

  /// Step the buffer position forward a specific number of steps
  fn step(&mut self, steps: usize) {
    self.pos += steps;
  }

  /// Change the buffer position
  fn seek(&mut self, pos: usize) {
    self.pos = pos;
  }

  /// Read a single byte and move the position one step forward
  fn read(&mut self) -> Result<u8, DnsError> {
    if self.pos >= 512 {
      return Err("End of buffer".into());
    }
    let res = self.buf[self.pos];
    self.pos += 1;

    Ok(res)
  }

  /// Get a single byte, without changing the buffer position
  fn get(&mut self, pos: usize) -> Result<u8, DnsError> {
    if pos >= 512 {
      return Err("End of buffer".into());
    }
    Ok(self.buf[pos])
  }

  /// Get a range of bytes
  fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], DnsError> {
    if start + len >= 512 {
      return Err("End of buffer".into());
    }
    Ok(&self.buf[start..start + len])
  }

  /// Read two bytes, stepping two steps forward
  fn read_u16(&mut self) -> Result<u16, DnsError> {
    let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

    Ok(res)
  }

  /// Read four bytes, stepping four steps forward
  fn read_u32(&mut self) -> Result<u32, DnsError> {
    let res = ((self.read()? as u32) << 24)
      | ((self.read()? as u32) << 16)
      | ((self.read()? as u32) << 8)
      | ((self.read()? as u32) << 0);

    Ok(res)
  }
  /// Read a qname
  ///
  /// The tricky part: Reading domain names, taking labels into consideration.
  /// Will take something like [3]www[6]google[3]com[0] and append
  /// www.google.com to outstr.
  fn read_qname(&mut self, outstr: &mut String) -> Result<(), DnsError> {
    // Since we might encounter jumps, we'll keep track of our position
    // locally as opposed to using the position within the struct. This
    // allows us to move the shared position to a point past our current
    // qname, while keeping track of our progress on the current qname
    // using this variable.
    let mut pos = self.pos();

    // track whether or not we've jumped
    let mut jumped = false;
    let max_jumps = 512;
    let mut jumps_performed = 0;

    // Our delimiter which we append for each label. Since we don't want a
    // dot at the beginning of the domain name we'll leave it empty for now
    // and set it to "." at the end of the first iteration.
    let mut delim = "";
    loop {
      // Dns Packets are untrusted data, so we need to be paranoid. Someone
      // can craft a packet with a cycle in the jump instructions. This guards
      // against such packets.
      if jumps_performed > max_jumps {
        return Err(
          format!("Limit of {} jumps exceeded", max_jumps)
            .as_str()
            .into(),
        );
      }

      // At this point, we're always at the beginning of a label. Recall
      // that labels start with a length byte.
      let len = self.get(pos)?;

      // If len has the two most significant bit are set, it represents a
      // jump to some other offset in the packet:
      if (len & 0xC0) == 0xC0 {
        // Update the buffer position to a point past the current
        // label. We don't need to touch it any further.
        if !jumped {
          if self.pos > self.buf.len() {
            return Err("too long!".into());
          }
          self.seek(pos + 2);
        }

        // Read another byte, calculate offset and perform the jump by
        // updating our local position variable
        let b2 = self.get(pos + 1)? as u16;
        let offset = (((len as u16) ^ 0xC0) << 8) | b2;
        pos = offset as usize;

        // Indicate that a jump was performed.
        jumped = true;
        jumps_performed += 1;

        continue;
      }
      // The base scenario, where we're reading a single label and
      // appending it to the output:
      else {
        // Move a single byte forward to move past the length byte.
        pos += 1;

        // Domain names are terminated by an empty label of length 0,
        // so if the length is zero we're done.
        if len == 0 {
          break;
        }

        // Append the delimiter to our output buffer first.
        outstr.push_str(delim);

        // Extract the actual ASCII bytes for this label and append them
        // to the output buffer.
        let str_buffer = self.get_range(pos, len as usize)?;
        outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

        delim = ".";

        // Move forward the full length of the label.
        pos += len as usize;
      }
    }

    if !jumped {
      if self.pos > self.buf.len() {
        return Err("too long!".into());
      }
      self.seek(pos);
    }

    Ok(())
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
      rq: if (raw_flags & 0b1000_0000_0000_0000) == 0 {
        DnsMessageType::Query
      } else {
        DnsMessageType::Response
      },
      query_type: if (raw_flags & 0b0100_0000_0000_0000) == 0 {
        MessageType::Standard
      } else {
        MessageType::Inverse
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
  pub(crate) fn parse(&mut self, buf: &[u8]) -> Result<&mut DnsMessage, DnsError> {
    self.tx_id = u16::from_be_bytes(buf[0..2].try_into()?);
    self.raw_flags = u16::from_be_bytes(buf[2..4].try_into()?);
    // multiple questions basically not supported by any dns server
    // https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query/4083071#4083071
    // self.questions = 1;
    self.questions = u16::from_be_bytes(buf[4..6].try_into()?);
    self.answers = self.questions; // TODO FIXME
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
    self.flags = Flags::new(self.raw_flags);
    self.host = self.remove_dot(self.read_qname(buf));
    Ok(self)
  }

  pub(crate) fn dns_message_as_byte_vec(&self) -> Result<Vec<u16>, DnsError> {
    let mut r = Vec::new();
    // keep the tx_id so we're part of the same dns 'conversation'
    r.push(self.tx_id);
    // then set our qr field to 1 (reply; 0 is query)
    let mut our_bits = self.raw_flags;
    our_bits |= 0b1000_0000_0000_0000;
    eprintln!("original bits: {:016b}", self.raw_flags);
    eprintln!("our bits:      {:016b}", our_bits);
    r.push(our_bits);
    r.push(self.questions);
    r.push(self.answer_rrs);
    r.push(self.authority_rrs);
    r.push(self.additional_rrs);
    for c in self.host.chars() {
      let mut _b = [0; 1];
      c.encode_utf16(&mut _b);
      r.push(_b[0]);
    }
    Ok(r)
  }

  // we have to step through one name chunk at a time
  //   g o o g l e   c o m
  // 6             3       0
  // ^ here
  //               ^ then here
  //                       ^ then here, and discover we're done
  pub(crate) fn read_qname(&self, buf: &[u8]) -> String {
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
        String::from_utf8(
          self
            .take_next(buf, &mut index, host_chunk_len.into())
            .unwrap(),
        )
        .unwrap()
        .as_str(),
      );
      host_chunk_len = buf[index];
      temp_host.push('.');
    }
    temp_host
  }

  pub(crate) fn generate_response(&mut self) -> Result<&DnsMessage, DnsError> {
    // should be, all we have to do is set the flag as a response instead of request
    // then give back our object to be serialized and sent over the network back to client
    self.set_rq_type(DnsMessageType::Response);
    //eprintln!("{:?}", self);
    Ok(self)
  }

  fn set_rq_type(&mut self, t: DnsMessageType) -> &DnsMessage {
    self.flags.rq = t;
    self
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
    *current_index += 1;
    let ret = buf[*current_index..*current_index + jump].to_vec();
    *current_index += jump;
    Ok(ret)
  }
}
