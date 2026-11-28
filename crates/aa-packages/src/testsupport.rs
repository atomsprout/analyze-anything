use aa_core::plugin::{Bytes, Tree};
use aa_core::{Artifact, Digests};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

pub(crate) struct Fixture {
    pub files: Vec<Artifact>,
    pub data: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    pub fn new(name: &str, kind: &str) -> Self {
        let mut fixture = Self { files: Vec::new(), data: BTreeMap::new() };
        fixture.files.push(Artifact {
            path: name.into(),
            parent: None,
            size: 0,
            digests: None,
            detected: None,
            kind: Some(kind.into()),
            entropy: None,
            unpacked_by: Some(kind.into()),
            facts: BTreeMap::from([("engine.container-listing".into(), json!({"complete":true}))]),
        });
        fixture
    }
    pub fn root(&self) -> &Artifact {
        self.files.iter().find(|file| file.parent.is_none()).expect("fixture root")
    }
    pub fn add(&mut self, relative: &str, bytes: &[u8]) {
        let parent = self.root().path.clone();
        let path = format!("{parent}/{relative}");
        self.files.push(Artifact {
            path: path.clone(),
            parent: Some(parent),
            size: bytes.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        });
        self.data.insert(path, bytes.to_vec());
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
    }
    pub fn replace(&mut self, relative: &str, bytes: &[u8]) {
        let path = format!("{}/{relative}", self.root().path);
        let file = self.files.iter_mut().find(|file| file.path == path).expect("replace existing fixture member");
        file.size = bytes.len() as u64;
        file.digests.as_mut().expect("fixture digests").sha256 = aa_core::sha256_hex(bytes);
        self.data.insert(path, bytes.to_vec());
    }
    pub fn zip(name: &str, bytes: &[u8]) -> Self {
        let mut fixture = Self::new(name, "zip");
        fixture.data.insert(name.into(), bytes.into());
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("licensed ZIP fixture");
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).expect("ZIP member");
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().expect("UTF-8 ZIP fixture name").to_string();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).expect("read ZIP fixture member");
            fixture.add(&name, &data);
        }
        fixture
    }
    pub fn tgz(name: &str, bytes: &[u8]) -> Self {
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(bytes).read_to_end(&mut tar).expect("fixture gzip");
        let mut fixture = Self::new(name, "tar");
        fixture.data.insert(name.into(), tar.clone());
        fixture.files[0].size = tar.len() as u64;
        let mut archive = tar::Archive::new(Cursor::new(tar));
        for entry in archive.entries().expect("fixture TAR") {
            let mut entry = entry.expect("fixture TAR member");
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = String::from_utf8(entry.path_bytes().to_vec()).expect("fixture path");
            let mut data = Vec::new();
            entry.read_to_end(&mut data).expect("TAR fixture bytes");
            fixture.add(&name, &data);
        }
        fixture
    }
}
impl Tree for Fixture {
    fn artifacts(&self) -> &[Artifact] {
        &self.files
    }
    fn read(&self, path: &str) -> std::io::Result<Bytes> {
        self.data.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "fixture path"))
    }
}
