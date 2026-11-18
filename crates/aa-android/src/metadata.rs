//! `<meta-data>` entries and resource strings that carry SDK keys and identifiers.

pub struct KeyKind {
    /// What the value is, for the report.
    pub what: &'static str,
    /// True when the value is a key or token and must be redacted; false for plain identifiers.
    pub secret: bool,
}

const fn k(what: &'static str, secret: bool) -> KeyKind {
    KeyKind { what, secret }
}

/// Exact `<meta-data android:name>` values of well-known SDKs.
const KNOWN: &[(&str, KeyKind)] = &[
    ("JPUSH_APPKEY", k("JPush app key", true)),
    ("PUSH_APPID", k("Getui push app id", false)),
    ("PUSH_APPKEY", k("Getui push app key", true)),
    ("PUSH_APPSECRET", k("Getui push app secret", true)),
    ("TencentMapSDK", k("Tencent Maps key", true)),
    ("UMENG_APPKEY", k("Umeng app key", true)),
    ("UMENG_MESSAGE_SECRET", k("Umeng push message secret", true)),
    ("com.amap.api.v2.apikey", k("AMap (Gaode) API key", true)),
    ("com.baidu.lbsapi.API_KEY", k("Baidu Maps API key", true)),
    ("com.bugsnag.android.API_KEY", k("Bugsnag API key", true)),
    ("com.facebook.sdk.ApplicationId", k("Facebook application id", false)),
    ("com.facebook.sdk.ClientToken", k("Facebook client token", true)),
    ("com.google.android.geo.API_KEY", k("Google Maps API key", true)),
    ("com.google.android.gms.ads.APPLICATION_ID", k("Google AdMob application id", false)),
    ("com.google.android.maps.v2.API_KEY", k("Google Maps API key", true)),
    ("com.google.android.nearby.messages.API_KEY", k("Google Nearby API key", true)),
    ("com.huawei.hms.client.appid", k("Huawei HMS app id", false)),
    ("com.mapbox.token", k("Mapbox access token", true)),
    ("com.onesignal.NotificationOpened.DEFAULT", k("OneSignal setting", false)),
    ("com.vivo.push.api_key", k("vivo push API key", true)),
    ("com.vivo.push.app_id", k("vivo push app id", false)),
    ("io.branch.sdk.BranchKey", k("Branch key", true)),
    ("io.fabric.ApiKey", k("Fabric/Crashlytics API key", true)),
    ("io.sentry.dsn", k("Sentry DSN", true)),
];

/// What a meta-data name holds, when its name is known or shaped like a key.
pub fn classify(name: &str) -> Option<KeyKind> {
    if let Some((_, kind)) = KNOWN.iter().find(|(n, _)| *n == name) {
        return Some(KeyKind { what: kind.what, secret: kind.secret });
    }
    let lower = name.to_ascii_lowercase();
    let shaped = ["api_key", "apikey", "api-key", "appkey", "app_key", "secret", "access_token", "accesstoken", "client_token"];
    shaped.iter().any(|s| lower.contains(s)).then_some(KeyKind { what: "key-like meta-data value", secret: true })
}

/// String resources the google-services Gradle plugin writes, and what they are.
pub const GOOGLE_SERVICES: &[(&str, KeyKind)] = &[
    ("default_web_client_id", k("OAuth web client id", false)),
    ("firebase_database_url", k("Firebase Realtime Database URL", false)),
    ("gcm_defaultSenderId", k("FCM sender id (project number)", false)),
    ("google_api_key", k("Google API key", true)),
    ("google_app_id", k("Firebase app id", false)),
    ("google_crash_reporting_api_key", k("Google API key (crash reporting)", true)),
    ("google_storage_bucket", k("Cloud Storage bucket", false)),
    ("project_id", k("Firebase project id", false)),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_shaped_names() {
        assert!(classify("com.google.android.geo.API_KEY").is_some_and(|k| k.secret));
        assert!(classify("com.facebook.sdk.ApplicationId").is_some_and(|k| !k.secret));
        assert!(classify("my.sdk.APP_KEY").is_some_and(|k| k.secret));
        assert!(classify("android.max_aspect").is_none());
    }
}
