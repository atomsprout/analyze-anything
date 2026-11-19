//! Signing certificates whose private keys are public: the test keys in the Android Open Source
//! Project (`build/target/product/security`). Anyone can sign with them, so a package signed
//! this way proves nothing about who built it. The fingerprints were computed from the
//! certificates in the AOSP `platform/build` repository.

/// `(SHA-256 of the certificate, name of the key)`.
pub const AOSP_TEST_KEYS: &[(&str, &str)] = &[
    ("a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc", "testkey"),
    ("c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8", "platform"),
    ("28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd", "shared"),
    ("465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e", "media"),
    ("e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee", "networkstack"),
    ("abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126", "sdk_sandbox"),
    ("a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35", "bluetooth"),
    ("fae9122a8721d6e2a196d2224dffcf773c9127e2bb956cbddb40b009192ffdfd", "nfc"),
];

pub fn aosp_test_key(sha256: &str) -> Option<&'static str> {
    AOSP_TEST_KEYS.iter().find(|(fingerprint, _)| *fingerprint == sha256).map(|(_, name)| *name)
}

/// True for the certificate Android Studio and the SDK tools generate for debug builds.
pub fn is_debug_certificate(subject: &str) -> bool {
    subject.split(", ").any(|part| part == "CN=Android Debug")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(aosp_test_key("a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"), Some("testkey"));
        assert_eq!(aosp_test_key("00"), None);
        assert!(is_debug_certificate("CN=Android Debug, O=Android, C=US"));
        assert!(!is_debug_certificate("CN=Android Debugger Inc"));
    }
}
