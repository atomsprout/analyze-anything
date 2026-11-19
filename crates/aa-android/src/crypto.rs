//! Signature verification with a certificate's public key (RustCrypto implementations).

use sha2::Digest;

use crate::der;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Md5 => md5::Md5::digest(data).to_vec(),
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha224 => sha2::Sha224::digest(data).to_vec(),
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Hash::Md5 => "MD5",
            Hash::Sha1 => "SHA-1",
            Hash::Sha224 => "SHA-224",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    /// From a digest algorithm OID.
    pub fn from_oid(oid: &str) -> Option<Hash> {
        Some(match oid {
            "1.2.840.113549.2.5" => Hash::Md5,
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.4" => Hash::Sha224,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    RsaPkcs1(Hash),
    /// RSASSA-PSS with MGF1 over the same hash and a salt as long as the hash.
    RsaPss(Hash),
    Ecdsa(Hash),
    Dsa(Hash),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    Invalid,
    /// The check could not be made; the text says why.
    Unsupported(String),
}

struct Spki<'a> {
    algorithm: String,
    params: Option<der::Tlv<'a>>,
    key: &'a [u8],
}

fn split_spki(spki: &[u8]) -> Option<Spki<'_>> {
    let (outer, _) = der::read(spki)?;
    let mut fields = der::items(outer.value);
    let algorithm = fields.next()?;
    let key = fields.next().filter(|t| t.tag == der::BIT_STRING)?.value.get(1..)?;
    let mut alg_fields = der::items(algorithm.value);
    let oid = der::oid_string(alg_fields.next()?.value);
    Some(Spki { algorithm: oid, params: alg_fields.next(), key })
}

fn two_integers(sequence: &[u8]) -> Option<(&[u8], &[u8])> {
    let (outer, _) = der::read(sequence)?;
    let mut fields = der::items(outer.value);
    let a = fields.next().filter(|t| t.tag == der::INTEGER)?;
    let b = fields.next().filter(|t| t.tag == der::INTEGER)?;
    Some((der::unsigned(a.value), der::unsigned(b.value)))
}

fn verify_rsa(spki: &Spki, scheme: Scheme, message: &[u8], signature: &[u8]) -> Outcome {
    use rsa::BigUint;
    let Some((n, e)) = two_integers(spki.key) else { return Outcome::Unsupported("RSA public key is malformed".into()) };
    let key = match rsa::RsaPublicKey::new_with_max_size(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e), 16384) {
        Ok(key) => key,
        Err(error) => return Outcome::Unsupported(format!("RSA public key rejected: {error}")),
    };
    let result = match scheme {
        Scheme::RsaPkcs1(hash) => {
            let digest = hash.digest(message);
            let padding = match hash {
                Hash::Md5 => rsa::Pkcs1v15Sign::new::<md5::Md5>(),
                Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                Hash::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                Hash::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                Hash::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                Hash::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            key.verify(padding, &digest, signature)
        }
        Scheme::RsaPss(hash) => {
            let digest = hash.digest(message);
            let padding = match hash {
                Hash::Sha256 => rsa::Pss::new_with_salt::<sha2::Sha256>(32),
                Hash::Sha384 => rsa::Pss::new_with_salt::<sha2::Sha384>(48),
                Hash::Sha512 => rsa::Pss::new_with_salt::<sha2::Sha512>(64),
                other => return Outcome::Unsupported(format!("RSASSA-PSS with {} is not supported", other.name())),
            };
            key.verify(padding, &digest, signature)
        }
        _ => return Outcome::Unsupported("the signature algorithm does not fit an RSA key".into()),
    };
    if result.is_ok() { Outcome::Valid } else { Outcome::Invalid }
}

fn verify_ec(spki: &Spki, hash: Hash, message: &[u8], signature: &[u8]) -> Outcome {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let curve = spki.params.filter(|p| p.tag == der::OID).map(|p| der::oid_string(p.value)).unwrap_or_default();
    let digest = hash.digest(message);
    let ok = match curve.as_str() {
        "1.2.840.10045.3.1.7" => {
            let (Ok(key), Ok(sig)) = (p256::ecdsa::VerifyingKey::from_sec1_bytes(spki.key), p256::ecdsa::Signature::from_der(signature))
            else {
                return Outcome::Invalid;
            };
            key.verify_prehash(&digest, &sig).is_ok()
        }
        "1.3.132.0.34" => {
            let (Ok(key), Ok(sig)) = (p384::ecdsa::VerifyingKey::from_sec1_bytes(spki.key), p384::ecdsa::Signature::from_der(signature))
            else {
                return Outcome::Invalid;
            };
            key.verify_prehash(&digest, &sig).is_ok()
        }
        "1.3.132.0.35" => {
            let (Ok(key), Ok(sig)) = (p521::ecdsa::VerifyingKey::from_sec1_bytes(spki.key), p521::ecdsa::Signature::from_der(signature))
            else {
                return Outcome::Invalid;
            };
            key.verify_prehash(&digest, &sig).is_ok()
        }
        other => return Outcome::Unsupported(format!("elliptic curve {other} is not supported")),
    };
    if ok { Outcome::Valid } else { Outcome::Invalid }
}

fn verify_dsa(spki: &Spki, hash: Hash, message: &[u8], signature: &[u8]) -> Outcome {
    use dsa::BigUint;
    use dsa::signature::hazmat::PrehashVerifier;
    let malformed = || Outcome::Unsupported("DSA public key is malformed".into());
    let Some(params) = spki.params else { return malformed() };
    let numbers: Vec<&[u8]> = der::items(params.value).filter(|t| t.tag == der::INTEGER).map(|t| der::unsigned(t.value)).collect();
    let [p, q, g] = numbers.as_slice() else { return malformed() };
    let Some((y, _)) = der::read(spki.key).filter(|(t, _)| t.tag == der::INTEGER) else { return malformed() };
    let big = BigUint::from_bytes_be;
    let Ok(components) = dsa::Components::from_components(big(p), big(q), big(g)) else {
        return Outcome::Unsupported("DSA parameters are not supported (size or validity)".into());
    };
    let Ok(key) = dsa::VerifyingKey::from_components(components, big(der::unsigned(y.value))) else { return malformed() };
    let Some((r, s)) = two_integers(signature) else { return Outcome::Invalid };
    let Ok(sig) = dsa::Signature::from_components(big(r), big(s)) else { return Outcome::Invalid };
    if key.verify_prehash(&hash.digest(message), &sig).is_ok() { Outcome::Valid } else { Outcome::Invalid }
}

/// Checks `signature` over `message` with the public key in `spki` (a DER subjectPublicKeyInfo).
pub fn verify(spki: &[u8], scheme: Scheme, message: &[u8], signature: &[u8]) -> Outcome {
    let Some(parts) = split_spki(spki) else { return Outcome::Unsupported("public key is malformed".into()) };
    match (parts.algorithm.as_str(), scheme) {
        ("1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10", Scheme::RsaPkcs1(_) | Scheme::RsaPss(_)) => {
            verify_rsa(&parts, scheme, message, signature)
        }
        ("1.2.840.10045.2.1", Scheme::Ecdsa(hash)) => verify_ec(&parts, hash, message, signature),
        ("1.2.840.10040.4.1", Scheme::Dsa(hash)) => verify_dsa(&parts, hash, message, signature),
        ("1.2.840.113549.1.1.1" | "1.2.840.10045.2.1" | "1.2.840.10040.4.1", _) => Outcome::Invalid,
        (other, _) => Outcome::Unsupported(format!("public key algorithm {other} is not supported")),
    }
}

/// The scheme a certificate's own signature uses, from its signature algorithm OID.
pub fn scheme_from_signature_oid(oid: &str) -> Option<Scheme> {
    Some(match oid {
        "1.2.840.113549.1.1.4" => Scheme::RsaPkcs1(Hash::Md5),
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => Scheme::RsaPkcs1(Hash::Sha1),
        "1.2.840.113549.1.1.14" => Scheme::RsaPkcs1(Hash::Sha224),
        "1.2.840.113549.1.1.11" => Scheme::RsaPkcs1(Hash::Sha256),
        "1.2.840.113549.1.1.12" => Scheme::RsaPkcs1(Hash::Sha384),
        "1.2.840.113549.1.1.13" => Scheme::RsaPkcs1(Hash::Sha512),
        "1.2.840.10045.4.1" => Scheme::Ecdsa(Hash::Sha1),
        "1.2.840.10045.4.3.1" => Scheme::Ecdsa(Hash::Sha224),
        "1.2.840.10045.4.3.2" => Scheme::Ecdsa(Hash::Sha256),
        "1.2.840.10045.4.3.3" => Scheme::Ecdsa(Hash::Sha384),
        "1.2.840.10045.4.3.4" => Scheme::Ecdsa(Hash::Sha512),
        "1.2.840.10040.4.3" => Scheme::Dsa(Hash::Sha1),
        "2.16.840.1.101.3.4.3.1" => Scheme::Dsa(Hash::Sha224),
        "2.16.840.1.101.3.4.3.2" => Scheme::Dsa(Hash::Sha256),
        _ => return None,
    })
}
