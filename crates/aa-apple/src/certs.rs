//! X.509 certificates and CMS signatures: what a certificate says, whether a signature made
//! with its key verifies, and how the certificates of a signature chain to each other.
//!
//! Nothing here decides trust. A chain is "anchored" only in the narrow sense that its last
//! certificate is byte-for-byte a root this crate knows by fingerprint; revocation and validity
//! at the present time are not looked at.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use serde_json::{Value, json};
use sha1::Digest;
use x509_cert::Certificate;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
/// Apple: a property list with the hashes of every code directory.
pub const OID_CDHASHES_PLIST: &str = "1.2.840.113635.100.9.1";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
/// Prefix of the certificate extensions Apple uses to mark what a certificate is for.
const APPLE_EXTENSIONS: &str = "1.2.840.113635.100.6.";

/// Root certificates recognised by SHA-256 fingerprint of their DER encoding.
const KNOWN_ROOTS: &[(&str, &str)] = &[
    ("b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", "Apple Root CA"),
    ("c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050", "Apple Root CA - G2"),
    ("63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179", "Apple Root CA - G3"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn from_oid(oid: &str) -> Option<Hash> {
        Some(match oid {
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            _ => return None,
        })
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Hash::Sha1 => "sha1",
            Hash::Sha256 => "sha256",
            Hash::Sha384 => "sha384",
            Hash::Sha512 => "sha512",
        }
    }
}

/// The outcome of checking one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid,
    /// The check could not be made; the text says why.
    Unchecked(String),
}

impl Verdict {
    pub fn label(&self) -> String {
        match self {
            Verdict::Valid => "valid".into(),
            Verdict::Invalid => "invalid".into(),
            Verdict::Unchecked(reason) => format!("unchecked: {reason}"),
        }
    }
}

/// The hash a signature algorithm implies, and whether it is RSA (`true`) or ECDSA (`false`).
/// `rsaEncryption` and `id-ecPublicKey` name no hash; the caller's hint is used.
fn signature_scheme(oid: &str, hint: Option<Hash>) -> Option<(bool, Hash)> {
    Some(match oid {
        OID_RSA => (true, hint?),
        "1.2.840.113549.1.1.5" => (true, Hash::Sha1),
        "1.2.840.113549.1.1.11" => (true, Hash::Sha256),
        "1.2.840.113549.1.1.12" => (true, Hash::Sha384),
        "1.2.840.113549.1.1.13" => (true, Hash::Sha512),
        OID_EC_KEY => (false, hint?),
        "1.2.840.10045.4.1" => (false, Hash::Sha1),
        "1.2.840.10045.4.3.2" => (false, Hash::Sha256),
        "1.2.840.10045.4.3.3" => (false, Hash::Sha384),
        "1.2.840.10045.4.3.4" => (false, Hash::Sha512),
        _ => return None,
    })
}

/// Checks `signature` over `message` with the public key `key`.
pub fn verify(
    key: &SubjectPublicKeyInfoOwned,
    algorithm: &ObjectIdentifier,
    hint: Option<Hash>,
    message: &[u8],
    signature: &[u8],
) -> Verdict {
    let algorithm = algorithm.to_string();
    let Some((rsa_signature, hash)) = signature_scheme(&algorithm, hint) else {
        return Verdict::Unchecked(format!("signature algorithm {algorithm} is not supported"));
    };
    let digest = hash.digest(message);
    let key_type = key.algorithm.oid.to_string();
    let key_bytes = key.subject_public_key.raw_bytes();
    match (key_type.as_str(), rsa_signature) {
        (OID_RSA, true) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let Ok(public) = rsa::RsaPublicKey::from_pkcs1_der(key_bytes) else {
                return Verdict::Unchecked("the RSA public key is malformed".into());
            };
            let scheme = match hash {
                Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                Hash::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                Hash::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                Hash::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            if public.verify(scheme, &digest, signature).is_ok() { Verdict::Valid } else { Verdict::Invalid }
        }
        (OID_EC_KEY, false) => {
            let curve = key.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok()).map(|oid| oid.to_string());
            match curve.as_deref() {
                Some(OID_P256) => {
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Ok(public), Ok(signature)) =
                        (p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes), p256::ecdsa::Signature::from_der(signature))
                    else {
                        return Verdict::Unchecked("the P-256 key or signature is malformed".into());
                    };
                    if public.verify_prehash(&digest, &signature).is_ok() { Verdict::Valid } else { Verdict::Invalid }
                }
                Some(OID_P384) => {
                    use p384::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Ok(public), Ok(signature)) =
                        (p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes), p384::ecdsa::Signature::from_der(signature))
                    else {
                        return Verdict::Unchecked("the P-384 key or signature is malformed".into());
                    };
                    if public.verify_prehash(&digest, &signature).is_ok() { Verdict::Valid } else { Verdict::Invalid }
                }
                other => Verdict::Unchecked(format!("elliptic curve {} is not supported", other.unwrap_or("(unnamed)"))),
            }
        }
        _ => Verdict::Unchecked(format!("key type {key_type} does not fit signature algorithm {algorithm}")),
    }
}

/// What a certificate says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub common_name: Option<String>,
    pub organizational_unit: Option<String>,
    pub organization: Option<String>,
    pub issuer: String,
    pub issuer_common_name: Option<String>,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    /// Seconds since 1970, for comparing with a signing time.
    pub validity: (u64, u64),
    pub sha256: String,
    pub is_ca: Option<bool>,
    pub self_issued: bool,
    /// Apple's marker extensions present in the certificate, as dotted OIDs.
    pub apple_extensions: Vec<String>,
    pub key: String,
}

fn attribute(name: &x509_cert::name::Name, oid: &str) -> Option<String> {
    for rdn in &name.0 {
        for pair in rdn.0.iter() {
            if pair.oid.to_string() == oid {
                let value = &pair.value;
                let text = value
                    .decode_as::<der::asn1::Utf8StringRef<'_>>()
                    .map(|s| s.as_str().to_string())
                    .or_else(|_| value.decode_as::<der::asn1::PrintableStringRef<'_>>().map(|s| s.as_str().to_string()))
                    .or_else(|_| value.decode_as::<der::asn1::Ia5StringRef<'_>>().map(|s| s.as_str().to_string()))
                    .unwrap_or_else(|_| String::from_utf8_lossy(value.value()).into_owned());
                return Some(text);
            }
        }
    }
    None
}

impl CertInfo {
    pub fn of(certificate: &Certificate) -> CertInfo {
        let tbs = &certificate.tbs_certificate;
        let der = certificate.to_der().unwrap_or_default();
        let key_type = tbs.subject_public_key_info.algorithm.oid.to_string();
        let key = match key_type.as_str() {
            OID_RSA => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                use rsa::traits::PublicKeyParts;
                match rsa::RsaPublicKey::from_pkcs1_der(tbs.subject_public_key_info.subject_public_key.raw_bytes()) {
                    Ok(public) => format!("RSA {}", public.n().bits()),
                    Err(_) => "RSA".to_string(),
                }
            }
            OID_EC_KEY => {
                let curve = tbs.subject_public_key_info.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
                match curve.map(|oid| oid.to_string()).as_deref() {
                    Some(OID_P256) => "EC P-256".to_string(),
                    Some(OID_P384) => "EC P-384".to_string(),
                    _ => "EC".to_string(),
                }
            }
            other => other.to_string(),
        };
        let extensions = tbs.extensions.as_deref().unwrap_or_default();
        let mut apple_extensions: Vec<String> =
            extensions.iter().map(|e| e.extn_id.to_string()).filter(|oid| oid.starts_with(APPLE_EXTENSIONS)).collect();
        apple_extensions.sort();
        let is_ca = tbs.get::<x509_cert::ext::pkix::BasicConstraints>().ok().flatten().map(|(_, constraints)| constraints.ca);
        CertInfo {
            subject: tbs.subject.to_string(),
            common_name: attribute(&tbs.subject, "2.5.4.3"),
            organizational_unit: attribute(&tbs.subject, "2.5.4.11"),
            organization: attribute(&tbs.subject, "2.5.4.10"),
            issuer: tbs.issuer.to_string(),
            issuer_common_name: attribute(&tbs.issuer, "2.5.4.3"),
            serial: hex::encode(tbs.serial_number.as_bytes()),
            not_before: tbs.validity.not_before.to_date_time().to_string(),
            not_after: tbs.validity.not_after.to_date_time().to_string(),
            validity: (tbs.validity.not_before.to_unix_duration().as_secs(), tbs.validity.not_after.to_unix_duration().as_secs()),
            sha256: hex::encode(sha2::Sha256::digest(&der)),
            is_ca,
            self_issued: tbs.subject == tbs.issuer,
            apple_extensions,
            key,
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "subject": self.subject,
            "common_name": self.common_name,
            "organizational_unit": self.organizational_unit,
            "organization": self.organization,
            "issuer": self.issuer,
            "issuer_common_name": self.issuer_common_name,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "sha256": self.sha256,
            "is_ca": self.is_ca,
            "apple_extensions": self.apple_extensions,
            "key": self.key,
        })
    }
}

/// How a chain of certificates ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// The last certificate is a root this crate knows by fingerprint.
    KnownRoot(&'static str),
    /// The last certificate signs itself but is not a known root.
    UnknownRoot,
    /// The issuer of the last certificate is not among the certificates given.
    Incomplete,
}

impl Anchor {
    pub fn label(&self) -> String {
        match self {
            Anchor::KnownRoot(name) => format!("known root: {name}"),
            Anchor::UnknownRoot => "self-signed root not known to this tool".into(),
            Anchor::Incomplete => "issuer certificate not included".into(),
        }
    }
}

/// The certificates from a signer up to where the chain ends, with each link checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// Signer first.
    pub certificates: Vec<CertInfo>,
    /// `links[i]` is the check of certificate `i`'s signature with the key of certificate
    /// `i + 1`; for a root at the end, with its own key.
    pub links: Vec<Verdict>,
    pub anchor: Anchor,
}

impl Chain {
    /// True when every link verified and the chain ends in a known root.
    pub fn anchored(&self) -> bool {
        matches!(self.anchor, Anchor::KnownRoot(_)) && self.links.iter().all(|link| *link == Verdict::Valid)
    }

    pub fn json(&self) -> Value {
        json!({
            "certificates": self.certificates.iter().map(CertInfo::json).collect::<Vec<_>>(),
            "links": self.links.iter().map(Verdict::label).collect::<Vec<_>>(),
            "anchor": self.anchor.label(),
        })
    }
}

fn signed_by(child: &Certificate, issuer: &Certificate) -> Verdict {
    let Ok(message) = child.tbs_certificate.to_der() else { return Verdict::Unchecked("the certificate cannot be re-encoded".into()) };
    verify(&issuer.tbs_certificate.subject_public_key_info, &child.signature_algorithm.oid, None, &message, child.signature.raw_bytes())
}

/// Builds the chain that starts at `certificates[start]`, using only the certificates given.
pub fn chain(certificates: &[Certificate], start: usize) -> Option<Chain> {
    let mut current = certificates.get(start)?;
    let mut chain = Chain { certificates: vec![CertInfo::of(current)], links: Vec::new(), anchor: Anchor::Incomplete };
    for _ in 0..8 {
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            chain.links.push(signed_by(current, current));
            let fingerprint = &chain.certificates[chain.certificates.len() - 1].sha256;
            chain.anchor = match KNOWN_ROOTS.iter().find(|(known, _)| known == fingerprint) {
                Some((_, name)) => Anchor::KnownRoot(name),
                None => Anchor::UnknownRoot,
            };
            return Some(chain);
        }
        // Several certificates can share a subject (reissued intermediates): prefer the one whose key verifies.
        let candidates: Vec<&Certificate> =
            certificates.iter().filter(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer).collect();
        let Some(first) = candidates.first() else { return Some(chain) };
        let (issuer, verdict) = candidates
            .iter()
            .map(|candidate| (*candidate, signed_by(current, candidate)))
            .find(|(_, verdict)| *verdict == Verdict::Valid)
            .unwrap_or_else(|| (*first, signed_by(current, first)));
        chain.links.push(verdict);
        chain.certificates.push(CertInfo::of(issuer));
        current = issuer;
    }
    Some(chain)
}

const BER_MAX_DEPTH: usize = 48;

/// Reads one BER element from `input` and appends its DER form to `out`. Returns the number of
/// bytes read. Indefinite lengths become definite and segmented octet strings are joined;
/// everything else is copied as it is, so DER input comes out unchanged.
fn ber_element(input: &[u8], out: &mut Vec<u8>, depth: usize) -> Option<usize> {
    if depth > BER_MAX_DEPTH {
        return None;
    }
    let first = *input.first()?;
    let mut at = 1;
    if first & 0x1f == 0x1f {
        // A tag number of 31 or more continues in the following bytes.
        loop {
            let byte = *input.get(at)?;
            at += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if at > 6 {
                return None;
            }
        }
    }
    let tag = &input[..at];
    let constructed = first & 0x20 != 0;
    let length_byte = *input.get(at)?;
    at += 1;
    let mut content = Vec::new();
    if length_byte == 0x80 {
        if !constructed {
            return None;
        }
        loop {
            if input.get(at..at + 2)? == [0, 0] {
                at += 2;
                break;
            }
            at += ber_element(&input[at..], &mut content, depth + 1)?;
        }
    } else {
        let length = if length_byte < 0x80 {
            length_byte as usize
        } else {
            let count = (length_byte & 0x7f) as usize;
            if count > 8 {
                return None;
            }
            let digits = input.get(at..at + count)?;
            at += count;
            digits.iter().try_fold(0usize, |total, digit| total.checked_mul(256)?.checked_add(*digit as usize))?
        };
        let body = input.get(at..at.checked_add(length)?)?;
        at += length;
        if constructed {
            let mut inner = 0;
            while inner < body.len() {
                inner += ber_element(&body[inner..], &mut content, depth + 1)?;
            }
        } else {
            content.extend_from_slice(body);
        }
    }
    if first == 0x24 {
        // A segmented OCTET STRING: its parts were converted to primitive strings; join them.
        let mut joined = Vec::new();
        let mut rest = &content[..];
        while !rest.is_empty() {
            let (&part_tag, after) = rest.split_first()?;
            if part_tag != 0x04 {
                return None;
            }
            let (&size, after) = after.split_first()?;
            let (length, after) = if size < 0x80 {
                (size as usize, after)
            } else {
                let count = (size & 0x7f) as usize;
                let digits = after.get(..count)?;
                (digits.iter().try_fold(0usize, |total, digit| total.checked_mul(256)?.checked_add(*digit as usize))?, &after[count..])
            };
            joined.extend_from_slice(after.get(..length)?);
            rest = &after[length..];
        }
        out.push(0x04);
        content = joined;
    } else {
        out.extend_from_slice(tag);
    }
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let digits = content.len().to_be_bytes();
        let skip = digits.iter().take_while(|digit| **digit == 0).count();
        out.push(0x80 | (digits.len() - skip) as u8);
        out.extend_from_slice(&digits[skip..]);
    }
    out.extend_from_slice(&content);
    Some(at)
}

/// Converts a BER encoding to DER, as far as CMS needs it. `None` when the input is malformed.
pub fn ber_to_der(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    ber_element(input, &mut out, 0)?;
    Some(out)
}

/// A parsed CMS `SignedData` with what this crate reads from its first signer.
pub struct Signed {
    data: SignedData,
    pub certificates: Vec<Certificate>,
}

/// What checking a detached or embedded CMS signature established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    pub chain: Option<Chain>,
    pub digest_algorithm: Option<&'static str>,
    /// Whether the signed `messageDigest` equals the digest of the content. `None`: no such attribute.
    pub digest_matches: Option<bool>,
    /// The signer's signature over the signed attributes (or over the content, without attributes).
    pub signature: Verdict,
    /// Signing time the signer claims, as text and as seconds since 1970.
    pub signing_time: Option<(String, u64)>,
    /// True when a timestamp-authority token is attached. Its own signature is not checked.
    pub timestamped: bool,
    /// Truncated code-directory hashes listed in Apple's signed attribute.
    pub cdhashes: Option<Vec<Vec<u8>>>,
}

impl Signed {
    /// Parses a DER `ContentInfo` holding `SignedData`.
    pub fn parse(der: &[u8]) -> Result<Signed, String> {
        // Apple writes CMS in BER (indefinite lengths, segmented strings); the parser wants DER.
        let info = match ContentInfo::from_der(der) {
            Ok(info) => info,
            Err(strict) => {
                let converted = ber_to_der(der).ok_or_else(|| format!("not a CMS structure: {strict}"))?;
                ContentInfo::from_der(&converted).map_err(|e| format!("not a CMS structure: {e}"))?
            }
        };
        if info.content_type.to_string() != OID_SIGNED_DATA {
            return Err(format!("CMS content type {} is not signed data", info.content_type));
        }
        let data: SignedData = info.content.decode_as().map_err(|e| format!("the CMS signed data is malformed: {e}"))?;
        let certificates = data
            .certificates
            .as_ref()
            .map(|set| {
                set.0
                    .iter()
                    .filter_map(|choice| match choice {
                        CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
                        CertificateChoices::Other(_) => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Signed { data, certificates })
    }

    /// The content carried inside the signature, when it is not detached.
    pub fn content(&self) -> Option<&[u8]> {
        self.data.encap_content_info.econtent.as_ref().map(|any| any.value())
    }

    fn signer(&self) -> Option<&SignerInfo> {
        self.data.signer_infos.0.iter().next()
    }

    fn signer_certificate(&self, signer: &SignerInfo) -> Option<usize> {
        match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(id) => self
                .certificates
                .iter()
                .position(|c| c.tbs_certificate.issuer == id.issuer && c.tbs_certificate.serial_number == id.serial_number),
            SignerIdentifier::SubjectKeyIdentifier(_) => None,
        }
    }

    /// Checks the first signer against `content` (the detached content, or `None` to use the
    /// embedded one).
    pub fn check(&self, content: Option<&[u8]>) -> Result<SignatureCheck, String> {
        let signer = self.signer().ok_or("the CMS structure has no signer")?;
        let content = content.or_else(|| self.content());
        let hash = Hash::from_oid(&signer.digest_alg.oid.to_string());
        let index = self.signer_certificate(signer);
        let chain = index.and_then(|index| chain(&self.certificates, index));
        let mut check = SignatureCheck {
            chain,
            digest_algorithm: hash.map(Hash::name),
            digest_matches: None,
            signature: Verdict::Unchecked("the signer's certificate is not included".into()),
            signing_time: None,
            timestamped: false,
            cdhashes: None,
        };
        let mut signed_bytes: Option<Vec<u8>> = None;
        if let Some(attributes) = &signer.signed_attrs {
            for attribute in attributes.iter() {
                let Some(value) = attribute.values.iter().next() else { continue };
                match attribute.oid.to_string().as_str() {
                    OID_MESSAGE_DIGEST => {
                        if let (Some(hash), Some(content), Ok(stored)) = (hash, content, value.decode_as::<der::asn1::OctetStringRef<'_>>())
                        {
                            check.digest_matches = Some(hash.digest(content) == stored.as_bytes());
                        }
                    }
                    OID_SIGNING_TIME => {
                        let time = value
                            .decode_as::<der::asn1::UtcTime>()
                            .map(|t| t.to_date_time())
                            .or_else(|_| value.decode_as::<der::asn1::GeneralizedTime>().map(|t| t.to_date_time()));
                        if let Ok(time) = time {
                            check.signing_time = Some((time.to_string(), time.unix_duration().as_secs()));
                        }
                    }
                    OID_CDHASHES_PLIST => {
                        if let Ok(octets) = value.decode_as::<der::asn1::OctetStringRef<'_>>()
                            && let Ok(plist) = plist::Value::from_reader(std::io::Cursor::new(octets.as_bytes()))
                            && let Some(list) = plist.as_dictionary().and_then(|d| d.get("cdhashes")).and_then(plist::Value::as_array)
                        {
                            check.cdhashes = Some(list.iter().filter_map(|v| v.as_data().map(<[u8]>::to_vec)).collect());
                        }
                    }
                    _ => {}
                }
            }
            // The signature covers the attributes encoded as a SET OF, which is how they re-encode.
            signed_bytes = attributes.to_der().ok();
        } else if let Some(content) = content {
            signed_bytes = Some(content.to_vec());
        }
        if let Some(attributes) = &signer.unsigned_attrs {
            check.timestamped = attributes.iter().any(|a| a.oid.to_string() == OID_TIMESTAMP_TOKEN);
        }
        if let Some(index) = index {
            check.signature = match &signed_bytes {
                Some(message) => verify(
                    &self.certificates[index].tbs_certificate.subject_public_key_info,
                    &signer.signature_algorithm.oid,
                    hash,
                    message,
                    signer.signature.as_bytes(),
                ),
                None => Verdict::Unchecked("there is nothing to check the signature against".into()),
            };
        }
        Ok(check)
    }
}

impl SignatureCheck {
    pub fn json(&self) -> Value {
        json!({
            "chain": self.chain.as_ref().map(Chain::json),
            "digest_algorithm": self.digest_algorithm,
            "digest_matches": self.digest_matches,
            "signature": self.signature.label(),
            "signing_time": self.signing_time.as_ref().map(|t| t.0.clone()),
            "timestamped": self.timestamped,
        })
    }

    /// The signer's certificate.
    pub fn leaf(&self) -> Option<&CertInfo> {
        self.chain.as_ref().and_then(|chain| chain.certificates.first())
    }
}

/// Parses DER certificates, skipping any that do not parse.
pub fn parse_certificates(ders: &[Vec<u8>]) -> Vec<Certificate> {
    ders.iter().filter_map(|der| Certificate::from_der(der).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_becomes_der() {
        // SEQUENCE (indefinite) { OCTET STRING (segmented, indefinite) { "ab", "c" }, INTEGER 5 }
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0x00, 0x00, 0x02, 0x01, 0x05, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber).expect("valid"), [0x30, 0x08, 0x04, 0x03, b'a', b'b', b'c', 0x02, 0x01, 0x05]);
        // DER passes through unchanged, long lengths included.
        let mut der = vec![0x30, 0x82, 0x01, 0x04, 0x04, 0x82, 0x01, 0x00];
        der.extend([7u8; 256]);
        assert_eq!(ber_to_der(&der).expect("valid"), der);
        for cut in 0..ber.len() {
            assert_eq!(ber_to_der(&ber[..cut]), None, "cut at {cut}");
        }
        // Unbounded nesting stops at the depth limit.
        assert_eq!(ber_to_der(&[0x30, 0x80].repeat(1000)), None);
        // An indefinite length on a primitive is not valid.
        assert_eq!(ber_to_der(&[0x04, 0x80, 0x00, 0x00]), None);
    }

    #[test]
    fn garbage_is_not_cms() {
        assert!(Signed::parse(&[]).is_err());
        assert!(Signed::parse(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
        assert!(Signed::parse(&[0xff; 64]).is_err());
    }

    #[test]
    fn unknown_algorithms_are_unchecked_not_invalid() {
        assert_eq!(signature_scheme("1.2.3.4", Some(Hash::Sha256)), None);
        assert_eq!(signature_scheme(OID_RSA, None), None);
        assert_eq!(signature_scheme(OID_RSA, Some(Hash::Sha1)), Some((true, Hash::Sha1)));
        assert_eq!(signature_scheme("1.2.840.10045.4.3.2", None), Some((false, Hash::Sha256)));
    }
}
