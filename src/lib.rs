use std::{
  io::{ErrorKind, Write},
  net::{Ipv4Addr, SocketAddr},
};

use mio::net::TcpStream;
pub use qprov;

use arrayref::array_refs;
pub use mio;
use qprov::{keys::CertificateChain, PubKeyPair, SecKeyPair};
use serde::{Deserialize, Serialize};
pub use uuid::Uuid;

// Q: is it safe to do this?
pub fn iv_from_hello(hello: KeyType) -> u128 {
  let (a, b) = array_refs![&hello.0, 16, 16];
  u128::from_be_bytes(*a) ^ u128::from_be_bytes(*b)
}

pub fn compare_hashes(lhs: KeyType, rhs: KeyType) -> bool {
  openssl::memcmp::eq(&lhs.0, &rhs.0)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyType([u8; Self::SIZE]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClientCrypter {
  key: KeyType,
  iv: u128,
  en_seq: u64,
  de_seq: u64,
}

impl ClientCrypter {
  const NONCE_LEN: usize = 16;
  const TAG_LEN: usize = 16;
  pub fn new(key: KeyType, iv: u128) -> Self {
    Self {
      key,
      iv,
      en_seq: 1,
      de_seq: 0,
    }
  }
  fn generage_aad(len: usize, id: Option<&[u8]>) -> Vec<u8> {
    let mut buf = len.to_be_bytes().to_vec();
    if let Some(id) = id {
      buf.extend_from_slice(id);
    }
    buf
  }

  fn generate_nonce(&mut self) -> [u8; Self::NONCE_LEN] {
    let nonce = (self.iv.wrapping_add(self.en_seq as u128)).to_be_bytes();
    self.en_seq += 1;
    nonce
  }

  fn update_nonce(&mut self, nonce: [u8; Self::NONCE_LEN]) -> bool {
    let req_seq = u128::from_be_bytes(nonce).wrapping_sub(self.iv) as u64;
    if req_seq <= self.de_seq {
      return false;
    }
    self.de_seq = req_seq;
    true
  }

  pub fn seal_in_place_append_tag_nonce(&mut self, data: &mut Vec<u8>, id: Option<&[u8]>) {
    let total_len = data.len() + Self::TAG_LEN + Self::NONCE_LEN;
    let mut tag = [0u8; Self::TAG_LEN];
    let nonce = self.generate_nonce();
    let mut encrypted = openssl::symm::encrypt_aead(
      openssl::symm::Cipher::aes_256_gcm(),
      &self.key.0,
      Some(&nonce),
      &Self::generage_aad(total_len, id),
      &data,
      &mut tag,
    )
    .unwrap();
    assert_eq!(encrypted.len(), data.len());
    encrypted.resize(total_len, 0);
    let len = encrypted.len();
    encrypted[len - Self::TAG_LEN - Self::NONCE_LEN..len - Self::NONCE_LEN].copy_from_slice(&tag);
    encrypted[len - Self::NONCE_LEN..].copy_from_slice(&nonce);
    drop(std::mem::replace(data, encrypted));
  }
  pub fn open(&mut self, data: &[u8], id: Option<&[u8]>) -> Option<Vec<u8>> {
    let total_len = data.len();
    if total_len <= Self::NONCE_LEN + Self::TAG_LEN {
      return None;
    }
    let nonce = arrayref::array_ref![data, total_len - Self::NONCE_LEN, 16];
    let tag = &data[total_len - Self::TAG_LEN - Self::NONCE_LEN..total_len - Self::NONCE_LEN];
    let encrypted = &data[..total_len - Self::TAG_LEN - Self::NONCE_LEN];
    let Ok(decrypted) = openssl::symm::decrypt_aead(openssl::symm::Cipher::aes_256_gcm(), &self.key.0, Some(nonce), &Self::generage_aad(total_len, id), encrypted, tag) else {
      return None;
    };
    if !self.update_nonce(*nonce) {
      return None;
    }
    Some(decrypted)
  }
}

impl KeyType {
  const SIZE: usize = 32;
  pub fn zero() -> Self {
    Self([0u8; Self::SIZE])
  }
  pub fn generate() -> Self {
    let mut key = [0u8; Self::SIZE];
    openssl::rand::rand_bytes(&mut key).unwrap();
    Self(key)
  }
  pub fn decapsulate(sk: &SecKeyPair, enc: &[u8]) -> Option<Self> {
    let plain = sk.decapsulate(&enc, Self::SIZE)?;
    let res = unsafe { *(plain.as_bytes().as_ptr() as *const [_; Self::SIZE]) };
    Some(Self(res))
  }
  pub fn encapsulate(pk: &PubKeyPair) -> Option<(Vec<u8>, Self)> {
    let (shared, plain) = pk.encapsulate(Self::SIZE)?;
    let res = unsafe { *(plain.as_bytes().as_ptr() as *const [_; Self::SIZE]) };
    Some((shared, Self(res)))
  }
}
impl std::ops::BitXor<Self> for KeyType {
  type Output = Self;
  fn bitxor(self, rhs: Self) -> Self::Output {
    let mut output = [0u8; Self::SIZE];
    for (out, (l, r)) in output
      .iter_mut()
      .zip(self.0.into_iter().zip(rhs.0.into_iter()))
    {
      *out = l ^ r;
    }
    Self(output)
  }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HelloMessage {
  pub chain: Vec<u8>,
  pub random: KeyType,
}

impl HelloMessage {
  pub fn chain(&self) -> Option<CertificateChain> {
    bincode::deserialize(&self.chain).ok()
  }
}

impl From<&CertificateChain> for HelloMessage {
  fn from(value: &CertificateChain) -> Self {
    let chain = bincode::serialize(&value).unwrap();
    let random = KeyType::generate();
    Self { chain, random }
  }
}

impl HelloMessage {
  pub fn from_serialized(chain: Vec<u8>) -> Self {
    let random = KeyType::generate();
    Self { chain, random }
  }
}

#[derive(Serialize, Deserialize)]
pub enum DecryptedHandshakeMessage {
  Ready { hash: KeyType },
  Welcome { ip: Ipv4Addr, mask: u8, id: Uuid },
}

impl DecryptedHandshakeMessage {
  pub fn encrypt(&self, crypter: &mut ClientCrypter) -> HandshakeMessage {
    let mut data = bincode::serialize(&self).unwrap();
    crypter.seal_in_place_append_tag_nonce(&mut data, None);
    HandshakeMessage::Ready(EncryptedHandshakeMessage(data))
  }
}

#[derive(Serialize, Deserialize)]
pub enum HandshakeMessage {
  Hello(HelloMessage),
  Premaster(Vec<u8>),
  Ready(EncryptedHandshakeMessage),
}

#[derive(Serialize, Deserialize)]
pub enum DecryptedMessage {
  IpPacket(Vec<u8>),
  KeepAlive,
}

impl DecryptedMessage {
  pub fn encrypt(&self, crypter: &mut ClientCrypter, id: Uuid) -> EncryptedMessage {
    let mut data = bincode::serialize(&self).unwrap();
    crypter.seal_in_place_append_tag_nonce(&mut data, Some(id.as_bytes()));
    EncryptedMessage(data, id)
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage(Vec<u8>, Uuid);

impl EncryptedMessage {
  pub fn decrypt(&self, crypter: &mut ClientCrypter) -> Option<DecryptedMessage> {
    let opened = crypter.open(&self.0, Some(self.1.as_bytes()))?;
    bincode::deserialize(&opened).ok()
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedHandshakeMessage(Vec<u8>);

impl EncryptedHandshakeMessage {
  pub fn decrypt(&self, crypter: &mut ClientCrypter) -> Option<DecryptedHandshakeMessage> {
    let opened = crypter.open(&self.0, None)?;
    bincode::deserialize(&opened).ok()
  }
}

struct Generator {
  part_size: usize,
  parts: Vec<Vec<u8>>,
}
impl Generator {
  fn into_inner(self) -> Vec<Vec<u8>> {
    return self.parts;
  }
}
impl Generator {
  fn new(part_size: usize) -> Self {
    Self {
      part_size,
      parts: vec![Vec::new()],
    }
  }
}
impl std::io::Write for Generator {
  fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
    let mut consumed = 0;
    while buf.len() != 0 {
      let last = self.parts.last_mut().unwrap();
      let vacant = self.part_size - last.len();
      let required = buf.len();
      if vacant == 0 {
        self.parts.push(Vec::new());
        continue;
      }
      let consuming = std::cmp::min(vacant, required);
      last.extend_from_slice(&buf[..consuming]);
      buf = &buf[consuming..];
      consumed += consuming;
    }
    Ok(consumed)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl EncryptedMessage {
  pub fn into_parts(&self, part_size: usize) -> Vec<MessagePart> {
    let mut messages = Generator::new(part_size);
    bincode::serialize_into(&mut messages, self).unwrap();
    let messages = messages.into_inner();
    let total = messages.len() as u32;
    let id = Uuid::new_v4();

    messages
      .into_iter()
      .enumerate()
      .map(|(i, data)| MessagePart {
        id,
        total,
        index: i as u32,
        data,
      })
      .collect()
  }
  pub fn get_sender_id(&self) -> Uuid {
    self.1
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePart {
  data: Vec<u8>,
  pub id: Uuid,
  pub total: u32,
  pub index: u32,
}

impl std::fmt::Display for MessagePart {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_fmt(format_args!(
      "MessagePart({} => {}/{})",
      self.id,
      self.index + 1,
      self.total
    ))
  }
}

#[derive(Debug, PartialEq, Eq)]
pub struct IndexPair(pub u32, pub usize);

impl PartialOrd for IndexPair {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    self.0.partial_cmp(&other.0)
  }
}

impl Ord for IndexPair {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.0.cmp(&other.0)
  }
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub struct IdPair(pub SocketAddr, pub Uuid);

pub struct MessagePartsCollection {
  count: usize,
  messages: Vec<Option<MessagePart>>,
}
impl MessagePartsCollection {
  pub fn new(total: u32) -> Self {
    Self {
      count: 0,
      messages: vec![None; total as usize],
    }
  }
  pub fn count(&self) -> usize {
    self.count
  }
  pub fn first_unreceived(&self) -> u32 {
    self
      .messages
      .iter()
      .enumerate()
      .skip_while(|(_, item)| item.is_some())
      .map(|(i, _)| i)
      .next()
      .unwrap_or(self.count) as u32
  }
  pub fn add(&mut self, message: MessagePart) -> std::io::Result<Option<EncryptedMessage>> {
    if message.total as usize != self.messages.len() {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Invalid total for message id",
      ));
    }
    let place = self
      .messages
      .get_mut(message.index as usize)
      .ok_or(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Index of of range",
      ))?;
    let old = std::mem::replace(place, Some(message));
    if let Some(_old) = old {
      // eprintln!("Replaced old message part: {}:{}", old.id, old.index);
    } else {
      self.count += 1;
    }
    self.drain()
  }
  fn drain(&mut self) -> std::io::Result<Option<EncryptedMessage>> {
    if self.count != self.messages.len() {
      return Ok(None);
    }
    let message_data = std::mem::replace(&mut self.messages, Vec::new())
      .into_iter()
      .map(Option::unwrap)
      .fold(
        Vec::with_capacity(self.count * 0xffff),
        |mut acc, mut item| {
          acc.append(&mut item.data);
          acc
        },
      );
    let message = bincode::deserialize(&message_data)
      .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
    Ok(Some(message))
  }
}

pub const MESSAGE_PART_LEN: usize = 0xFFFF - 80;

impl MessagePart {
  pub fn serialize_into(&self, buf: &mut [u8]) -> usize {
    let total_size = buf.len();
    let mut slice = &mut buf[..];
    bincode::serialize_into(&mut slice, self).unwrap();
    total_size - slice.len()
  }
}

pub fn send_unreliable(
  socket: &mio::net::UdpSocket,
  message: EncryptedMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let parts = message.into_parts(MESSAGE_PART_LEN);

  for part in parts.iter() {
    let len = part.serialize_into(buffer);
    socket.send(&buffer[..len])?;
  }
  Ok(())
}

pub fn send_unreliable_to(
  socket: &mio::net::UdpSocket,
  target: SocketAddr,
  message: EncryptedMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let parts = message.into_parts(MESSAGE_PART_LEN);

  for part in parts.iter() {
    let len = part.serialize_into(buffer);
    socket.send_to(&buffer[..len], target)?;
  }
  Ok(())
}

pub fn receive_unreliable(socket: &mio::net::UdpSocket, buffer: &mut [u8]) -> Vec<MessagePart> {
  let mut messages = Vec::new();
  loop {
    match socket.recv(buffer) {
      Ok(len) => {
        let Ok(part) = bincode::deserialize(&buffer[..len]) else {
          continue;
        };
        messages.push(part);
      }
      Err(err) if err.kind() == ErrorKind::WouldBlock => return messages,
      _ => {}
    }
  }
}

pub fn send_sized(
  stream: &mut std::net::TcpStream,
  message: HandshakeMessage,
) -> std::io::Result<()> {
  let len = bincode::serialized_size(&message)
    .map_err(|err| std::io::Error::new(ErrorKind::Other, err))? as u32;
  stream.write_all(&len.to_be_bytes())?;
  bincode::serialize_into(stream, &message)
    .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
}

pub struct BufferedTcpStream {
  stream: TcpStream,
  inbuf: Vec<u8>,
  outbuf: Vec<u8>,
  read_target: usize,
  read_size: usize,
}

impl From<TcpStream> for BufferedTcpStream {
  fn from(stream: TcpStream) -> Self {
    Self {
      stream,
      read_target: 0,
      inbuf: vec![],
      outbuf: vec![],
      read_size: 0,
    }
  }
}

impl BufferedTcpStream {
  pub fn read_sized(&mut self) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    if self.read_target == 0 {
      let mut len = [0u8; 4];
      if self.stream.peek(&mut len)? != 4 {
        return Err(ErrorKind::WouldBlock.into());
      }
      self.read_target = u32::from_be_bytes(len) as usize;
      if self.stream.read(&mut len)? != 4 {
        return Err(ErrorKind::UnexpectedEof.into());
      }
      self.inbuf.resize(self.read_target, 0);
    }
    let is_sero = loop {
      match self.stream.read(&mut self.inbuf[self.read_size..]) {
        Ok(0) => {
          // Reading 0 bytes means the other side has closed the
          // connection or is done writing, then so are we.
          break true;
        }
        Ok(n) => {
          self.read_size += n;
        }
        // Would block "errors" are the OS's way of saying that the
        // connection is not actually ready to perform this I/O operation.
        Err(ref err) if would_block(err) => break false,

        Err(ref err) if interrupted(err) => continue,
        // Other errors we'll consider fatal.
        Err(err) => {
          return Err(err);
        }
      }
    };
    if self.read_size != self.read_target {
      return Err(
        if is_sero {
          ErrorKind::ConnectionReset
        } else {
          ErrorKind::WouldBlock
        }
        .into(),
      );
    }
    self.read_target = 0;
    self.read_size = 0;
    Ok(std::mem::replace(&mut self.inbuf, vec![]))
  }
}

impl std::io::Write for BufferedTcpStream {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.outbuf.extend_from_slice(buf);
    Ok(buf.len())
  }
  fn flush(&mut self) -> std::io::Result<()> {
    if self.outbuf.is_empty() {
      return self.stream.flush();
    }
    loop {
      match self.stream.write(&self.outbuf) {
        Ok(n) => {
          self.outbuf.drain(0..n);
          if self.outbuf.is_empty() {
            return self.stream.flush();
          }
          return Err(ErrorKind::WouldBlock.into());
        }
        // Got interrupted (how rude!), we'll try again.
        Err(ref err) if interrupted(err) => continue,
        Err(err) => return Err(err),
      }
    }
  }
}

impl BufferedTcpStream {
  pub fn into_inner(self) -> TcpStream {
    self.stream
  }
}

pub fn would_block(err: &std::io::Error) -> bool {
  err.kind() == std::io::ErrorKind::WouldBlock
}

pub fn interrupted(err: &std::io::Error) -> bool {
  err.kind() == std::io::ErrorKind::Interrupted
}

#[derive(Debug)]
pub enum VpnError {
  WouldBlock,
  InvalidData,
  NotFound,
  PermissionDenied,
  Other(Box<dyn std::error::Error>),
}

impl std::fmt::Display for VpnError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_fmt(format_args!("{self:?}"))
  }
}

pub type VpnResult<T> = Result<T, VpnError>;

impl From<std::io::Error> for VpnError {
  fn from(value: std::io::Error) -> Self {
    match value.kind() {
      ErrorKind::WouldBlock => Self::WouldBlock,
      ErrorKind::InvalidData => Self::InvalidData,
      ErrorKind::PermissionDenied => Self::PermissionDenied,
      ErrorKind::NotFound => Self::NotFound,
      _ => Self::Other(Box::new(value)),
    }
  }
}

impl From<Box<bincode::ErrorKind>> for VpnError {
  fn from(value: Box<bincode::ErrorKind>) -> Self {
    match *value {
      bincode::ErrorKind::Io(err) => err.into(),
      _ => Self::InvalidData,
    }
  }
}
