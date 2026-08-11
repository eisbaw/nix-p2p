//! Strict, versioned Iroh node-address records carried in native pkarr packets.
//!
//! `_iroh.<signer>` remains interoperable with `iroh-dns` and contains only
//! `addr=` and `relay=` values.  The `_nix-p2p-iroh.<signer>` sibling name is
//! covered by the same Ed25519 signature and carries the lifecycle metadata
//! which stock Iroh address parsing intentionally does not retain.  Content
//! identifiers and inventory have no representation in this schema.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iroh::SecretKey;
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};
use url::{Host, Url};

use crate::transport::NodeId;

pub const NODE_PUBLICATION_SCHEMA: &str = "iroh-node-publication-v1";
pub const IROH_RECORD_NAME: &str = "_iroh";
pub const METADATA_RECORD_NAME: &str = "_nix-p2p-iroh";
pub const MAX_NAMESPACE_BYTES: usize = 128;
pub const MAX_RECIPIENT_BYTES: usize = 192;
pub const MAX_NODE_LOCATIONS: usize = 16;
const PKARR_HEADER_BYTES: usize = 32 + 64 + 8;
const METADATA_KEYS: [&str; 9] = [
    "schema",
    "namespace",
    "signer",
    "node-id",
    "recipient",
    "ttl-seconds",
    "sequence",
    "expires-unix-micros",
    "state",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeLocation {
    Direct(SocketAddr),
    Relay(String),
}

impl NodeLocation {
    pub fn direct(address: SocketAddr) -> Result<Self, NodeRecordError> {
        let address = normalize_socket_addr(address);
        validate_direct_address(address)?;
        Ok(Self::Direct(address))
    }

    pub fn relay(url: impl Into<String>) -> Result<Self, NodeRecordError> {
        let url = url.into();
        let canonical = Url::parse(&url)
            .map_err(|error| NodeRecordError::new(format!("invalid relay URL {url:?}: {error}")))?
            .to_string();
        validate_relay_url(&canonical)?;
        Ok(Self::Relay(canonical))
    }

    pub fn validate(&self) -> Result<(), NodeRecordError> {
        match self {
            Self::Direct(address) => validate_direct_address(*address),
            Self::Relay(url) => validate_relay_url(url),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    Live,
    Withdrawn,
}

impl PublicationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Withdrawn => "withdrawn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: NodeId,
    pub namespace: String,
    pub recipient: String,
    pub ttl_seconds: u32,
    pub sequence: u64,
    pub expires_unix_micros: u64,
    pub state: PublicationState,
    pub locations: Vec<NodeLocation>,
}

impl NodeRecord {
    pub fn is_visible_at(&self, unix_micros: u64) -> bool {
        self.expires_unix_micros > unix_micros
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRecordErrorKind {
    MalformedOrUntrusted,
    NoDialableCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecordError {
    kind: NodeRecordErrorKind,
    message: String,
}

impl NodeRecordError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            kind: NodeRecordErrorKind::MalformedOrUntrusted,
            message: message.into(),
        }
    }

    fn no_dialable_candidate(message: impl Into<String>) -> Self {
        Self {
            kind: NodeRecordErrorKind::NoDialableCandidate,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> NodeRecordErrorKind {
        self.kind
    }
}

impl fmt::Display for NodeRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NodeRecordError {}

pub fn validate_namespace(namespace: &str) -> Result<(), NodeRecordError> {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
        return Err(NodeRecordError::new(format!(
            "namespace length must be 1..={MAX_NAMESPACE_BYTES} bytes"
        )));
    }
    let bytes = namespace.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(NodeRecordError::new(
            "namespace must be lowercase ASCII alphanumeric/hyphen and start/end alphanumeric",
        ));
    }
    Ok(())
}

pub fn validate_recipient(recipient: &str) -> Result<(), NodeRecordError> {
    validate_token("recipient", recipient, MAX_RECIPIENT_BYTES)?;
    if recipient == "." || recipient == ".." || recipient.contains("..") {
        return Err(NodeRecordError::new(
            "recipient identifier contains an ambiguous dot traversal",
        ));
    }
    Ok(())
}

fn validate_token(label: &str, value: &str, max: usize) -> Result<(), NodeRecordError> {
    if value.is_empty() || value.len() > max {
        return Err(NodeRecordError::new(format!(
            "{label} length must be 1..={max} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(NodeRecordError::new(format!(
            "{label} contains characters outside [A-Za-z0-9._:-]"
        )));
    }
    Ok(())
}

pub fn validate_direct_address(address: SocketAddr) -> Result<(), NodeRecordError> {
    if normalize_socket_addr(address) != address {
        return Err(NodeRecordError::new(format!(
            "IPv4-mapped address {address} is not canonical; use its IPv4 socket form"
        )));
    }
    if address.port() == 0 {
        return Err(NodeRecordError::new(
            "direct publication address uses port zero",
        ));
    }
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST => {
            return Err(NodeRecordError::new(format!(
                "direct publication address {address} is not concrete unicast"
            )));
        }
        IpAddr::V6(ip) if ip.is_unspecified() || ip.is_multicast() => {
            return Err(NodeRecordError::new(format!(
                "direct publication address {address} is not concrete unicast"
            )));
        }
        IpAddr::V6(ip)
            if ip.is_unicast_link_local()
                && matches!(address, SocketAddr::V6(address) if address.scope_id() == 0) =>
        {
            return Err(NodeRecordError::new(format!(
                "link-local publication address {address} has no interface scope"
            )));
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn normalize_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ipv4| SocketAddr::new(IpAddr::V4(ipv4), v6.port()))
            .unwrap_or(SocketAddr::V6(v6)),
        ipv4 => ipv4,
    }
}

fn validate_relay_url(raw: &str) -> Result<(), NodeRecordError> {
    if raw.contains('=') {
        return Err(NodeRecordError::new(
            "relay URL contains '=' and cannot be represented canonically as one TXT attribute",
        ));
    }
    let url = Url::parse(raw)
        .map_err(|error| NodeRecordError::new(format!("invalid relay URL {raw:?}: {error}")))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(NodeRecordError::new(format!(
            "relay URL {raw:?} must use https with an explicit host"
        )));
    }
    if url.port() == Some(0) {
        return Err(NodeRecordError::new(format!(
            "relay URL {raw:?} uses port zero"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NodeRecordError::new(format!(
            "relay URL {raw:?} must not contain credentials, query, or fragment"
        )));
    }
    let forbidden_ip_literal = match url.host() {
        Some(Host::Ipv4(ip)) => {
            ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST
        }
        Some(Host::Ipv6(ip)) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST,
            None => ip.is_unspecified() || ip.is_multicast() || ip.is_unicast_link_local(),
        },
        Some(Host::Domain(_)) => false,
        None => unreachable!("explicit relay host was checked above"),
    };
    if forbidden_ip_literal {
        return Err(NodeRecordError::new(format!(
            "relay URL {raw:?} uses an IP-literal host that is not concretely dialable without ambient interface context"
        )));
    }
    if url.as_str() != raw {
        return Err(NodeRecordError::new(format!(
            "relay URL {raw:?} is not canonical; expected {:?}",
            url.as_str()
        )));
    }
    Ok(())
}

// Keeping every signed wire field explicit at the call site makes accidental
// defaults impossible in this security boundary.
#[allow(clippy::too_many_arguments)]
pub fn encode_node_record(
    secret_key: &SecretKey,
    namespace: &str,
    recipient: &str,
    ttl_seconds: u32,
    sequence: u64,
    expires_unix_micros: u64,
    state: PublicationState,
    locations: &[NodeLocation],
) -> Result<SignedPacket, NodeRecordError> {
    validate_namespace(namespace)?;
    validate_recipient(recipient)?;
    if ttl_seconds == 0 {
        return Err(NodeRecordError::new("record TTL must be positive"));
    }
    let expected_expiry = record_expiry(sequence, ttl_seconds)?;
    if expires_unix_micros != expected_expiry {
        return Err(NodeRecordError::new(format!(
            "record expiry {expires_unix_micros} is not exactly sequence plus TTL {expected_expiry}"
        )));
    }

    let mut canonical_locations = locations.to_vec();
    canonical_locations.sort();
    canonical_locations.dedup();
    if canonical_locations.len() > MAX_NODE_LOCATIONS {
        return Err(NodeRecordError::new(format!(
            "node record has {} locations, maximum is {MAX_NODE_LOCATIONS}",
            canonical_locations.len()
        )));
    }
    for location in &canonical_locations {
        match location {
            NodeLocation::Direct(address) => validate_direct_address(*address)?,
            NodeLocation::Relay(url) => validate_relay_url(url)?,
        }
    }
    match state {
        PublicationState::Live if canonical_locations.is_empty() => {
            return Err(NodeRecordError::new(
                "live node record requires at least one reachable location",
            ));
        }
        PublicationState::Withdrawn if !canonical_locations.is_empty() => {
            return Err(NodeRecordError::new(
                "withdrawal record must not contain locations",
            ));
        }
        _ => {}
    }

    let public_key = secret_key.public();
    let signer = public_key.to_z32();
    let origin = signer.as_str();
    let mut packet = Packet::new_reply(0);
    for location in &canonical_locations {
        let value = match location {
            NodeLocation::Direct(address) => format!("addr={address}"),
            NodeLocation::Relay(url) => format!("relay={url}"),
        };
        add_txt(&mut packet, IROH_RECORD_NAME, origin, ttl_seconds, &value)?;
    }
    let metadata = [
        format!("schema={NODE_PUBLICATION_SCHEMA}"),
        format!("namespace={namespace}"),
        format!("signer={signer}"),
        format!("node-id={}", NodeId::from_bytes(*public_key.as_bytes())),
        format!("recipient={recipient}"),
        format!("ttl-seconds={ttl_seconds}"),
        format!("sequence={sequence}"),
        format!("expires-unix-micros={expires_unix_micros}"),
        format!("state={}", state.as_str()),
    ];
    for value in metadata {
        add_txt(
            &mut packet,
            METADATA_RECORD_NAME,
            origin,
            ttl_seconds,
            &value,
        )?;
    }

    let encoded_dns = packet
        .build_bytes_vec_compressed()
        .map_err(|error| NodeRecordError::new(format!("encoding DNS packet: {error}")))?;
    if encoded_dns.len() + PKARR_HEADER_BYTES > SignedPacket::MAX_BYTES {
        return Err(NodeRecordError::new(format!(
            "signed node record is {} bytes, maximum is {}",
            encoded_dns.len() + PKARR_HEADER_BYTES,
            SignedPacket::MAX_BYTES
        )));
    }
    let signable = signable(sequence, &encoded_dns);
    let signature = secret_key.sign(&signable);
    let mut bytes = Vec::with_capacity(PKARR_HEADER_BYTES + encoded_dns.len());
    bytes.extend_from_slice(public_key.as_bytes());
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.extend_from_slice(&Timestamp::from_micros(sequence).to_be_bytes());
    bytes.extend_from_slice(&encoded_dns);
    SignedPacket::from_bytes(&bytes)
        .map_err(|error| NodeRecordError::new(format!("verifying encoded node record: {error}")))
}

fn add_txt<'a>(
    packet: &mut Packet<'a>,
    relative_name: &str,
    origin: &str,
    ttl: u32,
    value: &str,
) -> Result<(), NodeRecordError> {
    let name = Name::new(&format!("{relative_name}.{origin}"))
        .map_err(|error| NodeRecordError::new(format!("building DNS name: {error}")))?
        .into_owned();
    let mut txt = simple_dns::rdata::TXT::new();
    txt.add_string(value)
        .map_err(|error| NodeRecordError::new(format!("building DNS TXT value: {error}")))?;
    packet.answers.push(ResourceRecord::new(
        name,
        CLASS::IN,
        ttl,
        RData::TXT(txt.into_owned()),
    ));
    Ok(())
}

pub fn decode_node_record(bytes: &[u8]) -> Result<NodeRecord, NodeRecordError> {
    let signed = SignedPacket::from_bytes(bytes)
        .map_err(|error| NodeRecordError::new(format!("invalid signed packet: {error}")))?;
    let signer_key = signed.public_key();
    let signer = signer_key.to_z32();
    let iroh_name = format!("{IROH_RECORD_NAME}.{signer}");
    let metadata_name = format!("{METADATA_RECORD_NAME}.{signer}");
    if signed.encoded_packet().len() < 12 || signed.encoded_packet()[..4] != [0, 0, 0x80, 0] {
        return Err(NodeRecordError::new(
            "DNS header is not the canonical zero-id standard reply",
        ));
    }
    let packet = Packet::parse(signed.encoded_packet())
        .map_err(|error| NodeRecordError::new(format!("invalid DNS packet: {error}")))?;
    let canonical_dns = packet
        .build_bytes_vec_compressed()
        .map_err(|error| NodeRecordError::new(format!("re-encoding DNS packet: {error}")))?;
    if canonical_dns != signed.encoded_packet() {
        return Err(NodeRecordError::new(
            "DNS packet is not canonical or contains trailing bytes",
        ));
    }
    if !packet.questions.is_empty()
        || !packet.name_servers.is_empty()
        || !packet.additional_records.is_empty()
    {
        return Err(NodeRecordError::new(
            "node record must contain answers only",
        ));
    }

    let mut ttl: Option<u32> = None;
    let mut locations = Vec::new();
    let mut metadata = BTreeMap::<String, String>::new();
    let mut metadata_index = 0usize;
    for answer in &packet.answers {
        if answer.class != CLASS::IN {
            return Err(NodeRecordError::new("node record contains a non-IN answer"));
        }
        match ttl {
            Some(expected) if expected != answer.ttl => {
                return Err(NodeRecordError::new("node record TTLs are inconsistent"));
            }
            None => ttl = Some(answer.ttl),
            _ => {}
        }
        let RData::TXT(txt) = &answer.rdata else {
            return Err(NodeRecordError::new(
                "node record contains a non-TXT answer",
            ));
        };
        let value = String::try_from(txt.clone())
            .map_err(|error| NodeRecordError::new(format!("invalid TXT value: {error}")))?;
        let name = answer.name.to_string();
        if name == iroh_name {
            if metadata_index != 0 {
                return Err(NodeRecordError::new(
                    "node-location answer appears after lifecycle metadata",
                ));
            }
            let (key, raw) = split_attribute(&value)?;
            let location = match key {
                "addr" => {
                    let parsed: SocketAddr = raw.parse().map_err(|error| {
                        NodeRecordError::new(format!("invalid direct address {raw:?}: {error}"))
                    })?;
                    if parsed.to_string() != raw {
                        return Err(NodeRecordError::new(format!(
                            "signed direct address {raw:?} is not canonical"
                        )));
                    }
                    if normalize_socket_addr(parsed) != parsed {
                        return Err(NodeRecordError::new(format!(
                            "signed direct address {raw:?} uses noncanonical IPv4-mapped IPv6"
                        )));
                    }
                    NodeLocation::direct(parsed)?
                }
                "relay" => {
                    let location = NodeLocation::relay(raw)?;
                    if location != NodeLocation::Relay(raw.to_string()) {
                        return Err(NodeRecordError::new(format!(
                            "signed relay URL {raw:?} is not canonical"
                        )));
                    }
                    location
                }
                _ => {
                    return Err(NodeRecordError::new(format!(
                        "unknown interoperable Iroh attribute {key:?}"
                    )));
                }
            };
            if locations.contains(&location) {
                return Err(NodeRecordError::new("duplicate node location"));
            }
            if locations
                .last()
                .is_some_and(|previous| previous >= &location)
            {
                return Err(NodeRecordError::new(
                    "node locations are not in strict canonical order",
                ));
            }
            if locations.len() == MAX_NODE_LOCATIONS {
                return Err(NodeRecordError::new(format!(
                    "node record has more than {MAX_NODE_LOCATIONS} locations"
                )));
            }
            locations.push(location);
        } else if name == metadata_name {
            let (key, value) = split_attribute(&value)?;
            if METADATA_KEYS.get(metadata_index) != Some(&key) {
                return Err(NodeRecordError::new(format!(
                    "metadata attribute {key:?} is not in canonical position {metadata_index}"
                )));
            }
            metadata_index += 1;
            if metadata
                .insert(key.to_string(), value.to_string())
                .is_some()
            {
                return Err(NodeRecordError::new(format!(
                    "duplicate metadata attribute {key:?}"
                )));
            }
        } else {
            return Err(NodeRecordError::new(format!(
                "unexpected signed DNS answer name {name:?}"
            )));
        }
    }

    if metadata.len() != METADATA_KEYS.len()
        || METADATA_KEYS.iter().any(|key| !metadata.contains_key(*key))
    {
        return Err(NodeRecordError::new(format!(
            "metadata keys are not exactly {:?}",
            METADATA_KEYS
        )));
    }
    if metadata["schema"] != NODE_PUBLICATION_SCHEMA {
        return Err(NodeRecordError::new(format!(
            "unsupported node-record schema {:?}",
            metadata["schema"]
        )));
    }
    validate_namespace(&metadata["namespace"])?;
    validate_recipient(&metadata["recipient"])?;
    if metadata["signer"] != signer {
        return Err(NodeRecordError::new(
            "metadata signer does not match signature",
        ));
    }
    let node_id = NodeId::from_bytes(*signer_key.as_bytes());
    if metadata["node-id"] != node_id.to_hex() {
        return Err(NodeRecordError::new(
            "metadata node-id does not match signature",
        ));
    }
    let ttl_seconds = parse_u32("ttl-seconds", &metadata["ttl-seconds"])?;
    if ttl_seconds == 0 || ttl != Some(ttl_seconds) {
        return Err(NodeRecordError::new(
            "metadata TTL does not match positive DNS TTL",
        ));
    }
    let sequence = parse_u64("sequence", &metadata["sequence"])?;
    if sequence != signed.timestamp().as_micros() {
        return Err(NodeRecordError::new(
            "metadata sequence does not match signed pkarr timestamp",
        ));
    }
    let expires_unix_micros = parse_u64("expires-unix-micros", &metadata["expires-unix-micros"])?;
    let expected_expiry = record_expiry(sequence, ttl_seconds)?;
    if expires_unix_micros != expected_expiry {
        return Err(NodeRecordError::new(format!(
            "record expiry {expires_unix_micros} is not exactly sequence plus TTL {expected_expiry}"
        )));
    }
    let state = match metadata["state"].as_str() {
        "live" => PublicationState::Live,
        "withdrawn" => PublicationState::Withdrawn,
        other => {
            return Err(NodeRecordError::new(format!(
                "unknown publication state {other:?}"
            )));
        }
    };
    match state {
        PublicationState::Live if locations.is_empty() => {
            return Err(NodeRecordError::no_dialable_candidate(
                "live record has no locations",
            ));
        }
        PublicationState::Withdrawn if !locations.is_empty() => {
            return Err(NodeRecordError::new("withdrawal record contains locations"));
        }
        _ => {}
    }
    locations.sort();
    Ok(NodeRecord {
        node_id,
        namespace: metadata.remove("namespace").expect("checked"),
        recipient: metadata.remove("recipient").expect("checked"),
        ttl_seconds,
        sequence,
        expires_unix_micros,
        state,
        locations,
    })
}

fn split_attribute(value: &str) -> Result<(&str, &str), NodeRecordError> {
    let Some((key, value)) = value.split_once('=') else {
        return Err(NodeRecordError::new(format!(
            "TXT value {value:?} is not key=value"
        )));
    };
    if key.is_empty() || value.is_empty() || value.contains('=') {
        return Err(NodeRecordError::new(format!(
            "TXT value {value:?} is not one canonical key=value pair"
        )));
    }
    Ok((key, value))
}

fn parse_u64(label: &str, raw: &str) -> Result<u64, NodeRecordError> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NodeRecordError::new(format!(
            "{label} is not canonical unsigned decimal"
        )));
    }
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(NodeRecordError::new(format!(
            "{label} is not canonical decimal"
        )));
    }
    raw.parse()
        .map_err(|error| NodeRecordError::new(format!("invalid {label}: {error}")))
}

fn parse_u32(label: &str, raw: &str) -> Result<u32, NodeRecordError> {
    parse_u64(label, raw).and_then(|value| {
        value
            .try_into()
            .map_err(|_| NodeRecordError::new(format!("{label} exceeds u32")))
    })
}

fn record_expiry(sequence: u64, ttl_seconds: u32) -> Result<u64, NodeRecordError> {
    let ttl_micros = u64::from(ttl_seconds)
        .checked_mul(1_000_000)
        .ok_or_else(|| NodeRecordError::new("record TTL overflows u64 microseconds"))?;
    sequence
        .checked_add(ttl_micros)
        .ok_or_else(|| NodeRecordError::new("record expiry overflows u64 microseconds"))
}

fn signable(sequence: u64, dns_packet: &[u8]) -> Vec<u8> {
    let mut bytes = format!("3:seqi{sequence}e1:v{}:", dns_packet.len()).into_bytes();
    bytes.extend_from_slice(dns_packet);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_dns::endpoint_info::EndpointInfo;
    use simple_dns::{PacketFlag, QCLASS, QTYPE, Question, TYPE, rdata::A};

    fn base_live_packet(key: &SecretKey, sequence: u64) -> SignedPacket {
        encode_node_record(
            key,
            "run-123",
            "authority.test:v1",
            30,
            sequence,
            sequence + 30_000_000,
            PublicationState::Live,
            &[NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap()
    }

    fn sign_dns(key: &SecretKey, sequence: u64, dns: &[u8]) -> Vec<u8> {
        let signature = key.sign(&signable(sequence, dns));
        let mut bytes = Vec::with_capacity(PKARR_HEADER_BYTES + dns.len());
        bytes.extend_from_slice(key.public().as_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.extend_from_slice(&Timestamp::from_micros(sequence).to_be_bytes());
        bytes.extend_from_slice(dns);
        SignedPacket::from_bytes(&bytes)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn mutate_dns(
        key: &SecretKey,
        packet: &SignedPacket,
        sequence: u64,
        mutation: impl FnOnce(&mut Packet<'_>),
    ) -> Vec<u8> {
        let mut dns = Packet::parse(packet.encoded_packet()).unwrap();
        mutation(&mut dns);
        let encoded = dns.build_bytes_vec_compressed().unwrap();
        sign_dns(key, sequence, &encoded)
    }

    fn replace_txt(answer: &mut ResourceRecord<'_>, value: &str) {
        let mut txt = simple_dns::rdata::TXT::new();
        txt.add_string(value).unwrap();
        answer.rdata = RData::TXT(txt.into_owned());
    }

    #[test]
    fn signed_record_roundtrips_and_remains_iroh_compatible() {
        let key = SecretKey::generate();
        let locations = vec![
            NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
            NodeLocation::relay("https://relay.example.test/".to_string()).unwrap(),
        ];
        let packet = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            30,
            42,
            30_000_042,
            PublicationState::Live,
            &locations,
        )
        .unwrap();
        let decoded = decode_node_record(packet.as_bytes()).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.locations, locations);
        let endpoint = EndpointInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(
            endpoint.ip_addrs().copied().collect::<Vec<_>>(),
            vec!["127.0.0.1:4433".parse().unwrap()]
        );
        assert_eq!(endpoint.relay_urls().count(), 1);
        assert!(endpoint.user_data().is_none());
    }

    #[test]
    fn withdrawal_has_no_iroh_locations() {
        let key = SecretKey::generate();
        let packet = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            5,
            43,
            5_000_043,
            PublicationState::Withdrawn,
            &[],
        )
        .unwrap();
        let decoded = decode_node_record(packet.as_bytes()).unwrap();
        assert_eq!(decoded.state, PublicationState::Withdrawn);
        assert!(decoded.locations.is_empty());
        assert!(
            EndpointInfo::from_pkarr_signed_packet(&packet)
                .unwrap()
                .ip_addrs()
                .next()
                .is_none()
        );
    }

    #[test]
    fn invalid_direct_addresses_and_content_tokens_are_absent() {
        for raw in [
            "0.0.0.0:1",
            "[::]:1",
            "127.0.0.1:0",
            "224.0.0.1:1",
            "[fe80::1]:1",
        ] {
            assert!(NodeLocation::direct(raw.parse().unwrap()).is_err(), "{raw}");
        }
        assert!(NodeLocation::direct("[::ffff:0.0.0.0]:4433".parse().unwrap()).is_err());
        assert_eq!(
            NodeLocation::direct("[::ffff:192.0.2.1]:4433".parse().unwrap()).unwrap(),
            NodeLocation::Direct("192.0.2.1:4433".parse().unwrap())
        );
        let key = SecretKey::generate();
        let packet = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            5,
            1,
            5_000_001,
            PublicationState::Live,
            &[NodeLocation::direct("127.0.0.1:1".parse().unwrap()).unwrap()],
        )
        .unwrap();
        let decoded = String::from_utf8_lossy(packet.encoded_packet()).to_ascii_lowercase();
        for forbidden in ["narhash", "storepath", "closure", "inventory", "/nix/store"] {
            assert!(!decoded.contains(forbidden), "packet leaked {forbidden}");
        }
    }

    #[test]
    fn relay_ip_literals_must_be_concrete_unicast_but_domains_remain_allowed() {
        for raw in [
            "https://0.0.0.0/",
            "https://224.0.0.1/",
            "https://255.255.255.255/",
            "https://[::]/",
            "https://[ff02::1]/",
            "https://[::ffff:0.0.0.0]/",
            "https://[::ffff:224.0.0.1]/",
            "https://[::ffff:255.255.255.255]/",
            "https://[fe80::1]/",
        ] {
            let error = NodeLocation::relay(raw).unwrap_err();
            assert!(
                error.to_string().contains("not concretely dialable"),
                "unexpected error for {raw}: {error}"
            );
        }
        NodeLocation::relay("https://relay.example.test/").unwrap();
        NodeLocation::relay("https://192.0.2.1/").unwrap();
        NodeLocation::relay("https://[2001:db8::1]/").unwrap();
        assert!(NodeLocation::relay("https://relay.example.test:0/").is_err());
    }

    #[test]
    fn signed_dns_structure_mutations_are_rejected() {
        let key = SecretKey::generate();
        let sequence = 42;
        let packet = base_live_packet(&key, sequence);
        let signer = key.public().to_z32();

        let mut bad_header = packet.encoded_packet().to_vec();
        bad_header[0] = 1;
        assert!(decode_node_record(&sign_dns(&key, sequence, &bad_header)).is_err());

        let question = mutate_dns(&key, &packet, sequence, |dns| {
            dns.questions.push(Question::new(
                Name::new("question.test").unwrap().into_owned(),
                QTYPE::TYPE(TYPE::TXT),
                QCLASS::CLASS(CLASS::IN),
                false,
            ));
        });
        assert!(decode_node_record(&question).is_err());

        let authority = mutate_dns(&key, &packet, sequence, |dns| {
            dns.name_servers.push(dns.answers[0].clone());
        });
        assert!(decode_node_record(&authority).is_err());

        let additional = mutate_dns(&key, &packet, sequence, |dns| {
            dns.additional_records.push(dns.answers[0].clone());
        });
        assert!(decode_node_record(&additional).is_err());

        let class = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers[0].class = CLASS::CH;
        });
        assert!(decode_node_record(&class).is_err());

        let ttl = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers[0].ttl += 1;
        });
        assert!(decode_node_record(&ttl).is_err());

        let non_txt = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers[0].rdata = RData::A(A {
                address: u32::from_be_bytes([127, 0, 0, 1]),
            });
        });
        assert!(decode_node_record(&non_txt).is_err());

        let duplicate_metadata = mutate_dns(&key, &packet, sequence, |dns| {
            let metadata_name = format!("{METADATA_RECORD_NAME}.{signer}");
            let answer = dns
                .answers
                .iter()
                .find(|answer| answer.name.to_string() == metadata_name)
                .unwrap()
                .clone();
            dns.answers.push(answer);
        });
        assert!(decode_node_record(&duplicate_metadata).is_err());

        let unknown_metadata = mutate_dns(&key, &packet, sequence, |dns| {
            add_txt(dns, METADATA_RECORD_NAME, &signer, 30, "unknown=value").unwrap();
        });
        assert!(decode_node_record(&unknown_metadata).is_err());

        let unexpected_name = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers[0].name = Name::new("unexpected.test").unwrap().into_owned();
        });
        assert!(decode_node_record(&unexpected_name).is_err());

        let flags = mutate_dns(&key, &packet, sequence, |dns| {
            dns.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
        });
        assert!(decode_node_record(&flags).is_err());

        let metadata_reordered = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers.swap(1, 2);
        });
        let error = decode_node_record(&metadata_reordered).unwrap_err();
        assert!(error.to_string().contains("canonical position"));

        let multi_location = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            30,
            sequence,
            sequence + 30_000_000,
            PublicationState::Live,
            &[
                NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap(),
                NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap(),
            ],
        )
        .unwrap();
        let locations_reordered = mutate_dns(&key, &multi_location, sequence, |dns| {
            dns.answers.swap(0, 1);
        });
        let error = decode_node_record(&locations_reordered).unwrap_err();
        assert!(error.to_string().contains("strict canonical order"));

        let location_after_metadata = mutate_dns(&key, &packet, sequence, |dns| {
            dns.answers.swap(0, 1);
        });
        let error = decode_node_record(&location_after_metadata).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("appears after lifecycle metadata")
        );
    }

    #[test]
    fn signature_sequence_state_and_framing_mutations_are_rejected() {
        let key = SecretKey::generate();
        let sequence = 42;
        let packet = base_live_packet(&key, sequence);

        let mut signature = packet.as_bytes().to_vec();
        signature[40] ^= 1;
        assert!(decode_node_record(&signature).is_err());

        let sequence_mismatch = sign_dns(&key, sequence + 1, packet.encoded_packet());
        assert!(decode_node_record(&sequence_mismatch).is_err());

        let expiry_mismatch = mutate_dns(&key, &packet, sequence, |dns| {
            for answer in &mut dns.answers {
                if let RData::TXT(txt) = &answer.rdata
                    && String::try_from(txt.clone())
                        .unwrap()
                        .starts_with("expires-unix-micros=")
                {
                    replace_txt(answer, "expires-unix-micros=30000043");
                }
            }
        });
        let error = decode_node_record(&expiry_mismatch).unwrap_err();
        assert!(error.to_string().contains("not exactly sequence plus TTL"));

        for noncanonical in ["sequence=+42", "sequence=042"] {
            let bytes = mutate_dns(&key, &packet, sequence, |dns| {
                for answer in &mut dns.answers {
                    if let RData::TXT(txt) = &answer.rdata
                        && String::try_from(txt.clone())
                            .unwrap()
                            .starts_with("sequence=")
                    {
                        replace_txt(answer, noncanonical);
                    }
                }
            });
            assert!(
                decode_node_record(&bytes).is_err(),
                "accepted {noncanonical}"
            );
        }

        for noncanonical in ["addr=127.0.0.1:04433", "relay=https://RELAY.example.test/"] {
            let bytes = mutate_dns(&key, &packet, sequence, |dns| {
                let iroh_name = format!("{IROH_RECORD_NAME}.{}", key.public().to_z32());
                let answer = dns
                    .answers
                    .iter_mut()
                    .find(|answer| answer.name.to_string() == iroh_name)
                    .unwrap();
                replace_txt(answer, noncanonical);
            });
            assert!(
                decode_node_record(&bytes).is_err(),
                "accepted {noncanonical}"
            );
        }

        let mut trailing_dns = packet.encoded_packet().to_vec();
        trailing_dns.push(0);
        assert!(decode_node_record(&sign_dns(&key, sequence, &trailing_dns)).is_err());

        let live_without_location = mutate_dns(&key, &packet, sequence, |dns| {
            let iroh_name = format!("{IROH_RECORD_NAME}.{}", key.public().to_z32());
            dns.answers
                .retain(|answer| answer.name.to_string() != iroh_name);
        });
        assert!(decode_node_record(&live_without_location).is_err());

        let withdrawn_with_location = mutate_dns(&key, &packet, sequence, |dns| {
            for answer in &mut dns.answers {
                if let RData::TXT(txt) = &answer.rdata
                    && String::try_from(txt.clone()).unwrap() == "state=live"
                {
                    replace_txt(answer, "state=withdrawn");
                }
            }
        });
        assert!(decode_node_record(&withdrawn_with_location).is_err());
    }

    #[test]
    fn encoder_rejects_expiry_mismatch_and_overflow() {
        let key = SecretKey::generate();
        let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
        let mismatch = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            30,
            42,
            30_000_043,
            PublicationState::Live,
            std::slice::from_ref(&location),
        )
        .unwrap_err();
        assert!(
            mismatch
                .to_string()
                .contains("not exactly sequence plus TTL")
        );

        let overflow = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            1,
            u64::MAX,
            u64::MAX,
            PublicationState::Live,
            &[location],
        )
        .unwrap_err();
        assert!(overflow.to_string().contains("expiry overflows"));
    }

    #[test]
    fn encoder_rejects_public_variant_that_bypasses_relay_constructor() {
        let key = SecretKey::generate();
        let error = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            30,
            42,
            30_000_042,
            PublicationState::Live,
            &[NodeLocation::Relay(
                "https://RELAY.example.test/".to_string(),
            )],
        )
        .unwrap_err();
        assert!(error.to_string().contains("not canonical"));
    }

    #[test]
    fn over_limit_records_fail_in_encode_and_decode_without_truncation() {
        let key = SecretKey::generate();
        let locations = (1u16..=(MAX_NODE_LOCATIONS as u16 + 1))
            .map(|index| {
                let octet3 = (index / 250) as u8;
                let octet4 = (index % 250 + 1) as u8;
                NodeLocation::direct(SocketAddr::from(([10, 0, octet3, octet4], 4433))).unwrap()
            })
            .collect::<Vec<_>>();
        let error = encode_node_record(
            &key,
            "run-123",
            "authority.test:v1",
            30,
            42,
            30_000_042,
            PublicationState::Live,
            &locations,
        )
        .unwrap_err();
        assert!(error.to_string().contains("maximum is 16"));

        let base = base_live_packet(&key, 42);
        let over_limit = mutate_dns(&key, &base, 42, |dns| {
            let signer = key.public().to_z32();
            let metadata_start = dns
                .answers
                .iter()
                .position(|answer| answer.name.to_string().starts_with(METADATA_RECORD_NAME))
                .unwrap();
            let original_len = dns.answers.len();
            for index in 0..MAX_NODE_LOCATIONS {
                add_txt(
                    dns,
                    IROH_RECORD_NAME,
                    &signer,
                    30,
                    &format!("addr=127.0.0.{}:1", index + 2),
                )
                .unwrap();
            }
            let appended = dns.answers.split_off(original_len);
            dns.answers.splice(metadata_start..metadata_start, appended);
        });
        let error = decode_node_record(&over_limit).unwrap_err();
        assert!(error.to_string().contains("more than 16 locations"));
    }

    #[test]
    fn publication_source_has_no_lookup_content_or_lan_dependencies() {
        let production = [
            include_str!("iroh_node_record.rs"),
            include_str!("iroh_publication.rs"),
            include_str!("iroh_publication_authority.rs"),
            include_str!("pinned_http.rs"),
        ]
        .into_iter()
        .map(|source| {
            source
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .expect("split always returns one production prefix")
        })
        .collect::<Vec<_>>()
        .join("\n");
        for forbidden in [
            "crate::content",
            "crate::discovery",
            "crate::transport_iroh",
            "NarHash",
            "StorePath",
            "closure_membership",
            "content_inventory",
            "Mainline",
            "DnsPkarrResolver",
            "LocalSwarmDiscovery",
            "EndpointInfo::from",
        ] {
            assert!(
                !production.contains(forbidden),
                "publication boundary imported forbidden token {forbidden}"
            );
        }
    }
}
