use std::{
  io::ErrorKind,
  net::{Ipv4Addr, SocketAddr},
};

use arrayref::array_refs;
pub use mio;
use qprov::{keys::CertificateChain, Encapsulated, PubKeyPair, SecKeyPair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Q: is it safe to do this?
pub fn iv_from_hello(hello: KeyType) -> u128 {
  let (a, b) = array_refs![&hello.0, 16, 16];
  u128::from_be_bytes(*a) ^ u128::from_be_bytes(*b)
}

pub fn compare_hashes(_lhs: KeyType, _rhs: KeyType) -> bool {
  true
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
      en_seq: 0,
      de_seq: 0,
    }
  }
  fn generage_aad(len: usize) -> [u8; std::mem::size_of::<usize>()] {
    len.to_be_bytes()
  }

  fn generate_nonce(&mut self) -> [u8; Self::NONCE_LEN] {
    let nonce = (self.iv.wrapping_add(self.en_seq as u128)).to_be_bytes();
    self.en_seq += 1;
    nonce
  }

  pub fn update_nonce(&mut self, nonce: [u8; Self::NONCE_LEN]) -> bool {
    let req_seq = u128::from_be_bytes(nonce).wrapping_sub(self.iv) as u64;
    if req_seq <= self.de_seq {
      return false;
    }
    self.de_seq = req_seq;
    true
  }

  pub fn seal_in_place_append_tag_nonce(&mut self, data: &mut Vec<u8>) {
    let total_len = data.len() + Self::TAG_LEN + Self::NONCE_LEN;
    let mut tag = [0u8; Self::TAG_LEN];
    let nonce = self.generate_nonce();
    let mut encrypted = openssl::symm::encrypt_aead(
      openssl::symm::Cipher::aes_256_gcm(),
      &self.key.0,
      Some(&nonce),
      &Self::generage_aad(total_len),
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
  pub fn open_in_place(&self, data: &mut Vec<u8>) -> bool {
    let total_len = data.len();
    if total_len <= Self::NONCE_LEN + Self::TAG_LEN {
      return false;
    }
    let nonce = &data[total_len - Self::NONCE_LEN..];
    let tag = &data[total_len - Self::TAG_LEN - Self::NONCE_LEN..total_len - Self::NONCE_LEN];
    let encrypted = &data[..total_len - Self::TAG_LEN - Self::NONCE_LEN];
    let Ok(decrypted) = openssl::symm::decrypt_aead(openssl::symm::Cipher::aes_256_gcm(), &self.key.0, Some(nonce), &Self::generage_aad(total_len), encrypted, tag) else {
      return false;
    };
    drop(std::mem::replace(data, decrypted));
    true
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
  pub fn decapsulate(sk: &SecKeyPair, enc: &Encapsulated) -> Self {
    let plain = sk.decapsulate(&enc, Self::SIZE);
    let res = unsafe { *(plain.as_bytes().as_ptr() as *const [_; Self::SIZE]) };
    Self(res)
  }
  pub fn encapsulate(pk: &PubKeyPair) -> (Encapsulated, Self) {
    let (shared, plain) = pk.encapsulate(Self::SIZE);
    let res = unsafe { *(plain.as_bytes().as_ptr() as *const [_; Self::SIZE]) };
    (shared, Self(res))
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
  pub chain: CertificateChain,
  pub random: KeyType,
}

#[derive(Serialize, Deserialize)]
pub enum DecryptedMessage {
  Ready { hash: KeyType },
  Welcome { ip: Ipv4Addr, mask: u8 },
  IpPacket(Vec<u8>),
}

impl DecryptedMessage {
  pub fn encrypt(&self, crypter: &mut ClientCrypter) -> PlainMessage {
    match self {
      DecryptedMessage::Ready { .. } => {
        let mut data = bincode::serialize(&self).unwrap();
        crypter.seal_in_place_append_tag_nonce(&mut data);
        PlainMessage::Ready(EncryptedMessage(data))
      }
      _ => {
        let mut data = bincode::serialize(&self).unwrap();
        crypter.seal_in_place_append_tag_nonce(&mut data);
        PlainMessage::Encrypted(EncryptedMessage(data))
      }
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage(Vec<u8>);

impl EncryptedMessage {
  pub fn decrypt(mut self, crypter: &mut ClientCrypter) -> Option<DecryptedMessage> {
    if !crypter.open_in_place(&mut self.0) {
      return None;
    }
    bincode::deserialize(&self.0).ok()
  }
}

#[derive(Serialize, Deserialize)]
pub enum PlainMessage {
  Hello(HelloMessage),
  Premaster(Encapsulated),
  Ready(EncryptedMessage),
  Encrypted(EncryptedMessage),
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

impl PlainMessage {
  pub fn into_parts_without_ack(&self, part_size: usize) -> Vec<TransmissionMessage> {
    let mut messages = Generator::new(part_size);
    bincode::serialize_into(&mut messages, self).unwrap();
    let messages = messages.into_inner();
    let total = messages.len() as u32;
    let id = Uuid::new_v4();

    messages
      .into_iter()
      .enumerate()
      .map(|(i, data)| {
        TransmissionMessage::Part(MessagePart {
          requires_ack: false,
          id,
          total,
          index: i as u32,
          data,
        })
      })
      .collect()
  }
  pub fn into_parts_with_ack(&self, part_size: usize) -> (Uuid, Vec<TransmissionMessage>) {
    let mut messages = Generator::new(part_size);
    bincode::serialize_into(&mut messages, self).unwrap();
    let messages = messages.into_inner();
    let total = messages.len() as u32;
    let id = Uuid::new_v4();
    (
      id,
      messages
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
          TransmissionMessage::Part(MessagePart {
            requires_ack: true,
            id,
            total,
            index: i as u32,
            data,
          })
        })
        .collect(),
    )
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePart {
  data: Vec<u8>,
  pub id: Uuid,
  pub total: u32,
  pub index: u32,
  pub requires_ack: bool,
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
  pub fn add(&mut self, message: MessagePart) -> std::io::Result<Option<PlainMessage>> {
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
  fn drain(&mut self) -> std::io::Result<Option<PlainMessage>> {
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

#[derive(Serialize, Deserialize)]
pub enum TransmissionMessage {
  Part(MessagePart),
  Ack(Uuid, u32),
  Fin(Uuid),
}

impl TransmissionMessage {
  pub fn serialize_into(&self, buf: &mut [u8]) -> usize {
    let total_size = buf.len();
    let mut slice = &mut buf[..];
    bincode::serialize_into(&mut slice, self).unwrap();
    total_size - slice.len()
  }
}

pub fn send_ack(
  socket: &mut mio::net::UdpSocket,
  id: Uuid,
  ack: u32,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let msg = TransmissionMessage::Ack(id, ack);
  let len = msg.serialize_into(buffer);
  socket.send(&buffer[..len]).map(|_| ())
}

pub fn send_fin(
  socket: &mut mio::net::UdpSocket,
  id: Uuid,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let msg = TransmissionMessage::Fin(id);
  let len = msg.serialize_into(buffer);
  socket.send(&buffer[..len]).map(|_| ())
}

pub fn send_unreliable(
  socket: &mut mio::net::UdpSocket,
  message: PlainMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let parts = message.into_parts_without_ack(MESSAGE_PART_LEN);

  for part in parts.iter() {
    let len = part.serialize_into(buffer);
    socket.send(&buffer[..len])?;
  }
  Ok(())
}
const BULK_LEN: usize = 3;
const MAX_ATTEMPTS: usize = 10;

pub fn send_guaranteed(
  socket: &mut mio::net::UdpSocket,
  message: PlainMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let (id, parts) = message.into_parts_with_ack(MESSAGE_PART_LEN);
  let mut last_ack = 0;
  'outer: loop {
    for part in parts.iter().skip(last_ack).take(BULK_LEN) {
      let len = part.serialize_into(buffer);
      loop {
        match socket.send(&buffer[..len]) {
          Ok(_) => {
            break;
          }
          Err(err) if err.kind() == ErrorKind::WouldBlock => {}
          Err(err) => return Err(err)
        }
      }
    }
    let mut attempts = 0;
    loop {
      let len = loop {
        match socket.recv(buffer) {
          Ok(len) => break len,
          Err(err) if err.kind() == ErrorKind::WouldBlock => {
            if attempts > MAX_ATTEMPTS {
              continue 'outer;
            }
            attempts += 1;
            continue;
          }
          err => err?,
        };
      };
      let trans_msg: TransmissionMessage = bincode::deserialize(&buffer[..len])
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
      match trans_msg {
        TransmissionMessage::Ack(recv_id, ack) if id == recv_id => {
          last_ack = std::cmp::max(last_ack, ack as usize + 1);
        }
        TransmissionMessage::Fin(recv_id) if id == recv_id => break 'outer,
        _ => {}
      }
    }
  }
  Ok(())
}

pub fn send_ack_to(
  socket: &mut mio::net::UdpSocket,
  target: SocketAddr,
  id: Uuid,
  ack: u32,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let msg = TransmissionMessage::Ack(id, ack);
  let len = msg.serialize_into(buffer);
  socket.send_to(&buffer[..len], target).map(|_| ())
}

pub fn send_fin_to(
  socket: &mut mio::net::UdpSocket,
  target: SocketAddr,
  id: Uuid,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let msg = TransmissionMessage::Fin(id);
  let len = msg.serialize_into(buffer);
  socket.send_to(&buffer[..len], target).map(|_| ())
}

pub fn send_unreliable_to(
  socket: &mut mio::net::UdpSocket,
  target: SocketAddr,
  message: PlainMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let parts = message.into_parts_without_ack(MESSAGE_PART_LEN);

  for part in parts.iter() {
    let len = part.serialize_into(buffer);
    socket.send_to(&buffer[..len], target)?;
  }
  Ok(())
}

pub fn send_guaranteed_to(
  socket: &mut mio::net::UdpSocket,
  target: SocketAddr,
  message: PlainMessage,
  buffer: &mut [u8],
) -> std::io::Result<()> {
  let (id, parts) = message.into_parts_with_ack(MESSAGE_PART_LEN);
  let mut last_ack = 0;
  'outer: loop {
    for part in parts.iter().skip(last_ack).take(BULK_LEN) {
      let len = part.serialize_into(buffer);
      socket.send_to(&buffer[..len], target)?;
    }

    let mut attempts = 0;
    loop {
      let len = loop {
        match socket.recv_from(buffer) {
          Ok((len, sender)) if sender == target => break len,
          Err(err) if err.kind() == ErrorKind::WouldBlock => {
            if attempts > MAX_ATTEMPTS {
              continue 'outer;
            }
            attempts += 1;
            continue;
          }
          err => err?,
        };
      };
      let trans_msg: TransmissionMessage = bincode::deserialize(&buffer[..len])
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
      match trans_msg {
        TransmissionMessage::Ack(recv_id, ack) if id == recv_id => {
          last_ack = std::cmp::max(last_ack, ack as usize);
        }
        TransmissionMessage::Fin(recv_id) if id == recv_id => break 'outer,
        _ => {}
      }
    }
  }
  Ok(())
}

pub fn recv_blocking(
  socket: &mut mio::net::UdpSocket,
  buffer: &mut [u8],
) -> std::io::Result<usize> {
  loop {
    match socket.recv(buffer) {
      Ok(len) => return Ok(len),
      Err(err) if err.kind() == ErrorKind::WouldBlock => {}
      err => return err,
    }
  }
}

pub fn recv_rest_parts_blocking(
  socket: &mut mio::net::UdpSocket,
  part: MessagePart,
  buffer: &mut [u8],
) -> std::io::Result<PlainMessage> {
  let mut messages = MessagePartsCollection::new(part.total);
  let id = part.id;
  let message = if let Some(message) = messages.add(part)? {
    send_ack(socket, id, 0, buffer)?;
    send_fin(socket, id, buffer)?;
    message
  } else {
    loop {
      let len = recv_blocking(socket, buffer)?;
      let message: TransmissionMessage = bincode::deserialize(&buffer[..len])
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
      let TransmissionMessage::Part(part) = message else {
        continue;
      };
      if let Some(message) = messages.add(part)? {
        send_ack(socket, id, messages.first_unreceived() - 1, buffer)?;
        send_fin(socket, id, buffer)?;
        break message;
      }
      let first_unrecv = messages.first_unreceived();
      if first_unrecv == 0 {
        continue;
      }
      send_ack(socket, id, first_unrecv - 1, buffer)?;
    }
  };
  Ok(message)
}

pub fn recv_all_parts_blocking(
  socket: &mut mio::net::UdpSocket,
  buffer: &mut [u8],
) -> std::io::Result<PlainMessage> {
  let message = loop {
    let len = recv_blocking(socket, buffer)?;
    let message: TransmissionMessage = bincode::deserialize(&buffer[..len])
      .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
    if let TransmissionMessage::Part(part) = message {
      break part;
    }
  };

  recv_rest_parts_blocking(socket, message, buffer)
}

pub fn receive_unreliable(socket: &mut mio::net::UdpSocket, buffer: &mut [u8]) -> Vec<MessagePart> {
  let mut messages = Vec::new();
  loop {
    match socket.recv(buffer) {
      Ok(len) => {
        let Ok(TransmissionMessage::Part(part)) = bincode::deserialize(&buffer[..len]) else {
          continue;
        };
        messages.push(part);
      }
      Err(err) if err.kind() == ErrorKind::WouldBlock => return messages,
      _ => {}
    }
  }
}
