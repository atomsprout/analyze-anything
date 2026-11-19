//! Fingerprints of SDKs, app frameworks and packers, by class-package prefix, native library name
//! and file marker. The table is our own compilation from the vendors' public documentation and
//! from what their artifacts contain; it is a list of names, so a hit is "this name is present",
//! not "this SDK runs". Obfuscation that renames a vendor's packages hides it from this table.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Analytics,
    Ads,
    Attribution,
    CrashReporting,
    Push,
    Engagement,
    Payments,
    SocialLogin,
    Auth,
    Maps,
    Rtc,
    HotFix,
    Framework,
    Security,
    Library,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Analytics => "analytics",
            Category::Ads => "advertising",
            Category::Attribution => "attribution",
            Category::CrashReporting => "crash reporting / monitoring",
            Category::Push => "push messaging",
            Category::Engagement => "engagement / support",
            Category::Payments => "payments",
            Category::SocialLogin => "social login / sharing",
            Category::Auth => "authentication",
            Category::Maps => "maps / location",
            Category::Rtc => "real-time audio/video / messaging",
            Category::HotFix => "hot-fix / dynamic update",
            Category::Framework => "app framework",
            Category::Security => "security / anti-fraud",
            Category::Library => "library",
        }
    }

    pub fn as_str_zh(self) -> &'static str {
        match self {
            Category::Analytics => "统计分析",
            Category::Ads => "广告",
            Category::Attribution => "归因/安装来源追踪",
            Category::CrashReporting => "崩溃上报/性能监控",
            Category::Push => "消息推送",
            Category::Engagement => "用户运营/客服",
            Category::Payments => "支付",
            Category::SocialLogin => "社交登录/分享",
            Category::Auth => "身份认证",
            Category::Maps => "地图/定位",
            Category::Rtc => "实时音视频/即时通讯",
            Category::HotFix => "热修复/动态更新",
            Category::Framework => "应用框架",
            Category::Security => "安全/风控",
            Category::Library => "通用库",
        }
    }

    /// Categories whose purpose is to collect data about users or devices.
    pub fn is_tracker(self) -> bool {
        matches!(self, Category::Analytics | Category::Ads | Category::Attribution)
    }
}

pub struct Sdk {
    pub name: &'static str,
    pub vendor: &'static str,
    pub category: Category,
    /// Class-package prefixes with `/` separators, e.g. `com/appsflyer`.
    pub packages: &'static [&'static str],
    /// Native library file names. A `*` matches any run of characters.
    pub libs: &'static [&'static str],
    /// Paths inside the package; a trailing `/` marks a folder.
    pub files: &'static [&'static str],
}

const fn s(name: &'static str, vendor: &'static str, category: Category, packages: &'static [&'static str]) -> Sdk {
    Sdk { name, vendor, category, packages, libs: &[], files: &[] }
}

const fn f(
    name: &'static str,
    vendor: &'static str,
    category: Category,
    packages: &'static [&'static str],
    libs: &'static [&'static str],
    files: &'static [&'static str],
) -> Sdk {
    Sdk { name, vendor, category, packages, libs, files }
}

use Category::*;

pub const SDKS: &[Sdk] = &[
    // Google
    s("Firebase Analytics", "Google", Analytics, &["com/google/firebase/analytics", "com/google/android/gms/measurement"]),
    f(
        "Firebase Crashlytics",
        "Google",
        CrashReporting,
        &["com/google/firebase/crashlytics", "com/crashlytics/android"],
        &["libcrashlytics.so", "libcrashlytics-common.so"],
        &[],
    ),
    s("Firebase Cloud Messaging", "Google", Push, &["com/google/firebase/messaging", "com/google/firebase/iid"]),
    s("Firebase Remote Config", "Google", Library, &["com/google/firebase/remoteconfig"]),
    s("Firebase Authentication", "Google", Auth, &["com/google/firebase/auth"]),
    s("Cloud Firestore", "Google", Library, &["com/google/firebase/firestore"]),
    s("Firebase Realtime Database", "Google", Library, &["com/google/firebase/database"]),
    s("Cloud Storage for Firebase", "Google", Library, &["com/google/firebase/storage"]),
    s("Firebase Performance Monitoring", "Google", Analytics, &["com/google/firebase/perf"]),
    s("Firebase Dynamic Links", "Google", Attribution, &["com/google/firebase/dynamiclinks"]),
    s("Firebase In-App Messaging", "Google", Engagement, &["com/google/firebase/inappmessaging"]),
    s("Firebase App Check", "Google", Security, &["com/google/firebase/appcheck"]),
    s("Firebase App Distribution", "Google", Library, &["com/google/firebase/appdistribution"]),
    s("ML Kit", "Google", Library, &["com/google/mlkit", "com/google/firebase/ml"]),
    s("Google Mobile Ads (AdMob)", "Google", Ads, &["com/google/android/gms/ads"]),
    s("Google Analytics (legacy)", "Google", Analytics, &["com/google/android/gms/analytics"]),
    s("Google Tag Manager", "Google", Analytics, &["com/google/android/gms/tagmanager", "com/google/tagmanager"]),
    s("Google Play Billing", "Google", Payments, &["com/android/billingclient"]),
    s("Google Play Core (in-app update / review / feature delivery)", "Google", Library, &["com/google/android/play/core"]),
    s("Google Play Install Referrer", "Google", Attribution, &["com/android/installreferrer"]),
    s("Google Play services: Auth / Sign-In", "Google", SocialLogin, &["com/google/android/gms/auth"]),
    s("Google Play services: Maps", "Google", Maps, &["com/google/android/gms/maps", "com/google/maps/android"]),
    s("Google Play services: Location", "Google", Maps, &["com/google/android/gms/location"]),
    s("Google Play services: SafetyNet", "Google", Security, &["com/google/android/gms/safetynet"]),
    s("Google Play services: Cast", "Google", Library, &["com/google/android/gms/cast"]),
    s("Google Play services: Wallet (Google Pay)", "Google", Payments, &["com/google/android/gms/wallet"]),
    s("Google Play services: Games", "Google", Library, &["com/google/android/gms/games"]),
    s("Google Play services: Nearby", "Google", Library, &["com/google/android/gms/nearby"]),
    s("Google Play services: Vision / Barcode", "Google", Library, &["com/google/android/gms/vision"]),
    s("Google Play services (base)", "Google", Library, &["com/google/android/gms/common"]),
    s("Google Places", "Google", Maps, &["com/google/android/libraries/places"]),
    s("reCAPTCHA", "Google", Security, &["com/google/android/recaptcha"]),
    s("Google User Messaging Platform (consent)", "Google", Ads, &["com/google/android/ump"]),
    // Meta
    s("Facebook SDK: App Events", "Meta", Analytics, &["com/facebook/appevents"]),
    s("Facebook Login", "Meta", SocialLogin, &["com/facebook/login"]),
    s("Facebook Share", "Meta", SocialLogin, &["com/facebook/share"]),
    s("Meta Audience Network", "Meta", Ads, &["com/facebook/ads"]),
    s("Flipper (debugging tool)", "Meta", Library, &["com/facebook/flipper"]),
    s("Fresco (image loading)", "Meta", Library, &["com/facebook/fresco", "com/facebook/drawee"]),
    // Attribution and analytics
    s("AppsFlyer", "AppsFlyer", Attribution, &["com/appsflyer"]),
    s("Adjust", "Adjust", Attribution, &["com/adjust/sdk"]),
    s("Branch", "Branch Metrics", Attribution, &["io/branch"]),
    s("Kochava", "Kochava", Attribution, &["com/kochava"]),
    s("Singular", "Singular", Attribution, &["com/singular/sdk"]),
    s("Tenjin", "Tenjin", Attribution, &["com/tenjin"]),
    s("Amplitude", "Amplitude", Analytics, &["com/amplitude"]),
    s("Mixpanel", "Mixpanel", Analytics, &["com/mixpanel/android"]),
    s("Segment", "Twilio Segment", Analytics, &["com/segment/analytics"]),
    s("Flurry", "Yahoo", Analytics, &["com/flurry"]),
    s("Braze (Appboy)", "Braze", Engagement, &["com/braze", "com/appboy"]),
    s("CleverTap", "CleverTap", Engagement, &["com/clevertap/android"]),
    s("MoEngage", "MoEngage", Engagement, &["com/moengage"]),
    s("Leanplum", "Leanplum", Engagement, &["com/leanplum"]),
    s("Localytics", "Upland", Analytics, &["com/localytics"]),
    s("Heap", "Heap", Analytics, &["com/heapanalytics"]),
    s("PostHog", "PostHog", Analytics, &["com/posthog"]),
    s("Countly", "Countly", Analytics, &["ly/count/android"]),
    s("Matomo", "Matomo", Analytics, &["org/matomo"]),
    s("Snowplow", "Snowplow", Analytics, &["com/snowplowanalytics"]),
    s("Adobe Experience Platform / Analytics", "Adobe", Analytics, &["com/adobe/marketing/mobile", "com/adobe/mobile"]),
    s("comScore", "comScore", Analytics, &["com/comscore"]),
    s("Nielsen", "Nielsen", Analytics, &["com/nielsen/app"]),
    s("UXCam (session recording)", "UXCam", Analytics, &["com/uxcam"]),
    s("Smartlook (session recording)", "Smartlook", Analytics, &["com/smartlook"]),
    s("FullStory (session recording)", "FullStory", Analytics, &["com/fullstory"]),
    s("Microsoft Clarity (session recording)", "Microsoft", Analytics, &["com/microsoft/clarity"]),
    s("Yandex AppMetrica", "Yandex", Analytics, &["com/yandex/metrica", "io/appmetrica"]),
    s("MyTracker", "VK", Analytics, &["com/my/tracker"]),
    // Crash reporting and monitoring
    f("Sentry", "Sentry", CrashReporting, &["io/sentry"], &["libsentry.so", "libsentry-android.so"], &[]),
    f("Bugsnag", "SmartBear", CrashReporting, &["com/bugsnag"], &["libbugsnag-ndk.so"], &[]),
    s("ACRA", "ACRA", CrashReporting, &["org/acra"]),
    s("Instabug", "Instabug", CrashReporting, &["com/instabug"]),
    s("Visual Studio App Center", "Microsoft", CrashReporting, &["com/microsoft/appcenter"]),
    s("New Relic", "New Relic", CrashReporting, &["com/newrelic/agent"]),
    s("Datadog", "Datadog", CrashReporting, &["com/datadog/android"]),
    s("Dynatrace", "Dynatrace", CrashReporting, &["com/dynatrace/android"]),
    s("AppDynamics", "Cisco", CrashReporting, &["com/appdynamics"]),
    s("Embrace", "Embrace", CrashReporting, &["io/embrace"]),
    s("Rollbar", "Rollbar", CrashReporting, &["com/rollbar"]),
    // Push and engagement
    s("OneSignal", "OneSignal", Push, &["com/onesignal"]),
    s("Airship (Urban Airship)", "Airship", Push, &["com/urbanairship"]),
    s("Pushwoosh", "Pushwoosh", Push, &["com/pushwoosh"]),
    s("Batch", "Batch", Push, &["com/batch/android"]),
    s("Iterable", "Iterable", Engagement, &["com/iterable"]),
    s("Customer.io", "Customer.io", Engagement, &["io/customer"]),
    s("Klaviyo", "Klaviyo", Engagement, &["com/klaviyo"]),
    s("Intercom", "Intercom", Engagement, &["io/intercom"]),
    s("Zendesk", "Zendesk", Engagement, &["zendesk", "com/zendesk"]),
    s("Freshchat", "Freshworks", Engagement, &["com/freshchat"]),
    // Advertising
    s("Unity Ads", "Unity", Ads, &["com/unity3d/ads", "com/unity3d/services"]),
    s("AppLovin", "AppLovin", Ads, &["com/applovin"]),
    s("ironSource", "Unity", Ads, &["com/ironsource"]),
    s("Vungle (Liftoff)", "Liftoff", Ads, &["com/vungle"]),
    s("Chartboost", "Chartboost", Ads, &["com/chartboost"]),
    s("InMobi", "InMobi", Ads, &["com/inmobi"]),
    s("Mintegral", "Mintegral", Ads, &["com/mbridge", "com/mintegral"]),
    s("Pangle / CSJ (穿山甲)", "ByteDance", Ads, &["com/bytedance/sdk/openadsdk", "com/pgl"]),
    s("AdColony", "Digital Turbine", Ads, &["com/adcolony"]),
    s("Tapjoy", "Unity", Ads, &["com/tapjoy"]),
    s("Start.io (StartApp)", "Start.io", Ads, &["com/startapp"]),
    s("MoPub", "AppLovin", Ads, &["com/mopub"]),
    s("Amazon Publisher Services", "Amazon", Ads, &["com/amazon/device/ads"]),
    s("Criteo", "Criteo", Ads, &["com/criteo"]),
    s("Smaato", "Smaato", Ads, &["com/smaato"]),
    s("Fyber (Digital Turbine)", "Digital Turbine", Ads, &["com/fyber"]),
    s("Ogury", "Ogury", Ads, &["com/ogury", "io/presage"]),
    s("Yandex Mobile Ads", "Yandex", Ads, &["com/yandex/mobile/ads"]),
    s("myTarget", "VK", Ads, &["com/my/target"]),
    s("BidMachine", "BidMachine", Ads, &["io/bidmachine"]),
    s("PubMatic", "PubMatic", Ads, &["com/pubmatic"]),
    s("Verve (PubNative)", "Verve", Ads, &["net/pubnative"]),
    s("Moloco", "Moloco", Ads, &["com/moloco"]),
    s("Tencent GDT (优量汇)", "Tencent", Ads, &["com/qq/e"]),
    s("Baidu Mobads (百青藤)", "Baidu", Ads, &["com/baidu/mobads"]),
    s("Kuaishou Ads (快手联盟)", "Kuaishou", Ads, &["com/kwad/sdk"]),
    s("Sigmob", "Sigmob", Ads, &["com/sigmob"]),
    s("Huawei Ads", "Huawei", Ads, &["com/huawei/hms/ads", "com/huawei/openalliance/ad"]),
    // China: analytics, push, platform SDKs
    f("Tencent Bugly", "Tencent", CrashReporting, &["com/tencent/bugly"], &["libBugly*.so"], &[]),
    s("Tencent TBS / X5 WebView", "Tencent", Library, &["com/tencent/smtt"]),
    s("WeChat Open SDK (微信)", "Tencent", SocialLogin, &["com/tencent/mm/opensdk", "com/tencent/mm/sdk"]),
    s("Tencent MTA (移动分析)", "Tencent", Analytics, &["com/tencent/stat"]),
    s("Tencent Beacon (灯塔)", "Tencent", Analytics, &["com/tencent/beacon"]),
    s("QQ Connect (QQ 互联)", "Tencent", SocialLogin, &["com/tencent/tauth", "com/tencent/connect"]),
    f("Tencent MMKV", "Tencent", Library, &["com/tencent/mmkv"], &["libmmkv.so"], &[]),
    s("Tencent Tinker", "Tencent", HotFix, &["com/tencent/tinker"]),
    s("Tencent Matrix (APM)", "Tencent", CrashReporting, &["com/tencent/matrix"]),
    s("Tencent Maps / Location", "Tencent", Maps, &["com/tencent/map", "com/tencent/tencentmap", "com/tencent/lbssearch"]),
    f(
        "Tencent Cloud IM / TRTC",
        "Tencent",
        Rtc,
        &["com/tencent/imsdk", "com/tencent/trtc", "com/tencent/liteav"],
        &["libliteavsdk.so"],
        &[],
    ),
    s("Tencent Push (TPNS / 信鸽)", "Tencent", Push, &["com/tencent/android/tpush"]),
    s("Alipay SDK (支付宝)", "Ant Group", Payments, &["com/alipay/sdk", "com/alipay/android/app"]),
    s("Alibaba UTDID (device id)", "Alibaba", Analytics, &["com/ut/device", "com/ta/utdid2"]),
    f("Alibaba Sophix", "Alibaba", HotFix, &["com/taobao/sophix"], &["libsophix.so"], &[]),
    f("Alibaba AndFix", "Alibaba", HotFix, &["com/alipay/euler/andfix"], &["libandfix.so"], &[]),
    s("Alibaba ARouter", "Alibaba", Library, &["com/alibaba/android/arouter"]),
    s("Fastjson", "Alibaba", Library, &["com/alibaba/fastjson"]),
    s("Alibaba Cloud Push", "Alibaba", Push, &["com/alibaba/sdk/android/push"]),
    s("Alibaba Cloud Mobile Analytics", "Alibaba", Analytics, &["com/alibaba/sdk/android/man"]),
    s("Alibaba Cloud OSS", "Alibaba", Library, &["com/alibaba/sdk/android/oss"]),
    f(
        "Alibaba Security Guard (无线保镖)",
        "Alibaba",
        Security,
        &["com/alibaba/wireless/security"],
        &["libsgmain.so", "libsgsecuritybody.so", "libsgmainso-*.so"],
        &[],
    ),
    s("Umeng Analytics (友盟)", "Alibaba", Analytics, &["com/umeng/analytics", "com/umeng/commonsdk"]),
    s("Umeng Push (友盟推送)", "Alibaba", Push, &["com/umeng/message"]),
    s("Umeng Share (友盟分享)", "Alibaba", SocialLogin, &["com/umeng/socialize"]),
    f("AMap (高德地图)", "Alibaba", Maps, &["com/amap/api", "com/autonavi"], &["libAMapSDK*.so"], &[]),
    s("Baidu Maps (百度地图)", "Baidu", Maps, &["com/baidu/mapapi"]),
    f("Baidu Location (百度定位)", "Baidu", Maps, &["com/baidu/location"], &["liblocSDK*.so"], &[]),
    s("Baidu Mobstat (百度统计)", "Baidu", Analytics, &["com/baidu/mobstat"]),
    s("Baidu Push", "Baidu", Push, &["com/baidu/android/pushservice"]),
    s("JPush (极光推送)", "Aurora Mobile", Push, &["cn/jpush"]),
    s("JAnalytics (极光统计)", "Aurora Mobile", Analytics, &["cn/jiguang/analytics"]),
    f("JCore (极光核心库)", "Aurora Mobile", Push, &["cn/jiguang"], &["libjcore*.so"], &[]),
    f("Getui (个推)", "Getui", Push, &["com/igexin"], &["libgetuiext*.so"], &[]),
    s("Huawei HMS Core", "Huawei", Library, &["com/huawei/hms"]),
    s("Huawei Push", "Huawei", Push, &["com/huawei/hms/push"]),
    s("Huawei Analytics", "Huawei", Analytics, &["com/huawei/hms/analytics"]),
    s("Huawei AppGallery Connect", "Huawei", Library, &["com/huawei/agconnect"]),
    s("Xiaomi MiPush (小米推送)", "Xiaomi", Push, &["com/xiaomi/mipush", "com/xiaomi/push"]),
    s("OPPO Push (HeyTap)", "OPPO", Push, &["com/heytap/msp/push", "com/heytap/mcssdk", "com/coloros/mcssdk"]),
    s("vivo Push", "vivo", Push, &["com/vivo/push"]),
    s("Meizu Push", "Meizu", Push, &["com/meizu/cloud/pushsdk"]),
    s("Honor Push", "Honor", Push, &["com/hihonor/push"]),
    s("Sensors Data (神策数据)", "Sensors Data", Analytics, &["com/sensorsdata/analytics"]),
    s("GrowingIO", "GrowingIO", Analytics, &["com/growingio"]),
    s("TalkingData", "TalkingData", Analytics, &["com/tendcloud"]),
    s("ShareSDK / MobSDK", "Mob", SocialLogin, &["cn/sharesdk", "com/mob"]),
    s("ByteDance AppLog (火山引擎)", "ByteDance", Analytics, &["com/bytedance/applog", "com/ss/android/common/applog"]),
    s("Douyin / TikTok Open SDK", "ByteDance", SocialLogin, &["com/bytedance/sdk/open", "com/tiktok/open"]),
    s("Kuaishou Open SDK", "Kuaishou", SocialLogin, &["com/kwai/opensdk"]),
    s("Robust", "Meituan", HotFix, &["com/meituan/robust"]),
    f("Weibo SDK (微博)", "Sina", SocialLogin, &["com/sina/weibo/sdk"], &["libweibosdkcore.so"], &[]),
    s("UnionPay (银联)", "China UnionPay", Payments, &["com/unionpay"]),
    s("NetEase Yunxin IM (云信)", "NetEase", Rtc, &["com/netease/nimlib"]),
    s("NetEase Yidun (易盾)", "NetEase", Security, &["com/netease/nis"]),
    s("iFlytek (讯飞语音)", "iFlytek", Library, &["com/iflytek"]),
    f("ijkplayer", "Bilibili", Library, &["tv/danmaku/ijk"], &["libijkplayer.so", "libijkffmpeg.so"], &[]),
    s("RongCloud (融云)", "RongCloud", Rtc, &["io/rong"]),
    s("Easemob (环信)", "Easemob", Rtc, &["com/hyphenate", "com/easemob"]),
    s("LeanCloud", "LeanCloud", Library, &["cn/leancloud", "com/avos"]),
    // Real-time communication
    f("Agora", "Agora", Rtc, &["io/agora"], &["libagora-rtc-sdk.so", "libagora-rtc-sdk-jni.so"], &[]),
    f("ZEGO", "ZEGO", Rtc, &["im/zego", "com/zego"], &["libzegoliveroom.so", "libZegoExpressEngine.so"], &[]),
    s("Twilio", "Twilio", Rtc, &["com/twilio"]),
    f("WebRTC", "Google", Rtc, &["org/webrtc"], &["libjingle_peerconnection_so.so"], &[]),
    s("Jitsi Meet SDK", "8x8", Rtc, &["org/jitsi"]),
    s("Zoom SDK", "Zoom", Rtc, &["us/zoom"]),
    s("Vonage Video (OpenTok)", "Vonage", Rtc, &["com/opentok"]),
    s("LiveKit", "LiveKit", Rtc, &["io/livekit"]),
    // Payments
    s("Stripe", "Stripe", Payments, &["com/stripe/android"]),
    s("PayPal", "PayPal", Payments, &["com/paypal"]),
    s("Braintree", "PayPal", Payments, &["com/braintreepayments"]),
    s("Adyen", "Adyen", Payments, &["com/adyen"]),
    s("Square In-App Payments", "Block", Payments, &["sqip"]),
    s("Razorpay", "Razorpay", Payments, &["com/razorpay"]),
    s("RevenueCat", "RevenueCat", Payments, &["com/revenuecat/purchases"]),
    s("Paytm", "Paytm", Payments, &["com/paytm", "net/one97"]),
    s("Klarna", "Klarna", Payments, &["com/klarna"]),
    s("Mercado Pago", "Mercado Libre", Payments, &["com/mercadopago"]),
    // Social login and identity
    s("Twitter Kit", "X", SocialLogin, &["com/twitter/sdk"]),
    s("Kakao SDK", "Kakao", SocialLogin, &["com/kakao/sdk", "com/kakao/auth"]),
    s("LINE SDK", "LY Corporation", SocialLogin, &["com/linecorp/linesdk"]),
    s("VK SDK", "VK", SocialLogin, &["com/vk/api/sdk", "com/vk/sdk"]),
    s("Naver Login", "Naver", SocialLogin, &["com/navercorp/nid", "com/nhn/android/naverlogin"]),
    s("Snap Kit", "Snap", SocialLogin, &["com/snapchat/kit", "com/snap/corekit"]),
    s("Auth0", "Okta", Auth, &["com/auth0"]),
    s("Okta", "Okta", Auth, &["com/okta"]),
    s("Microsoft Authentication Library (MSAL)", "Microsoft", Auth, &["com/microsoft/identity"]),
    s("AppAuth", "OpenID Foundation", Auth, &["net/openid/appauth"]),
    s("AWS SDK / Amplify", "Amazon", Library, &["com/amazonaws", "com/amplifyframework"]),
    // Maps
    f("Mapbox", "Mapbox", Maps, &["com/mapbox"], &["libmapbox-gl.so"], &[]),
    s("HERE SDK", "HERE", Maps, &["com/here/sdk", "com/here/android"]),
    s("osmdroid (OpenStreetMap)", "osmdroid", Maps, &["org/osmdroid"]),
    f("MapLibre", "MapLibre", Maps, &["org/maplibre"], &["libmaplibre.so"], &[]),
    // Common libraries
    s("OkHttp", "Square", Library, &["okhttp3"]),
    s("Retrofit", "Square", Library, &["retrofit2"]),
    s("Glide", "Bump Technologies", Library, &["com/bumptech/glide"]),
    s("Picasso", "Square", Library, &["com/squareup/picasso"]),
    s("Coil", "Coil", Library, &["coil", "coil3"]),
    s("RxJava", "ReactiveX", Library, &["io/reactivex"]),
    s("Kotlin coroutines", "JetBrains", Library, &["kotlinx/coroutines"]),
    s("Gson", "Google", Library, &["com/google/gson"]),
    s("Moshi", "Square", Library, &["com/squareup/moshi"]),
    s("Jackson", "FasterXML", Library, &["com/fasterxml/jackson"]),
    s("Protocol Buffers", "Google", Library, &["com/google/protobuf"]),
    s("gRPC", "CNCF", Library, &["io/grpc"]),
    s("Ktor", "JetBrains", Library, &["io/ktor"]),
    s("Volley", "Google", Library, &["com/android/volley"]),
    s("Dagger / Hilt", "Google", Library, &["dagger"]),
    s("Koin", "Kotzilla", Library, &["org/koin"]),
    s("Room", "Google", Library, &["androidx/room"]),
    s("WorkManager", "Google", Library, &["androidx/work"]),
    s("Media3 / ExoPlayer", "Google", Library, &["androidx/media3", "com/google/android/exoplayer2"]),
    f("Realm", "MongoDB", Library, &["io/realm"], &["librealm-jni.so"], &[]),
    f("SQLCipher", "Zetetic", Library, &["net/sqlcipher", "net/zetetic"], &["libsqlcipher.so"], &[]),
    s("Bouncy Castle", "Legion of the Bouncy Castle", Library, &["org/bouncycastle", "org/spongycastle"]),
    f("Conscrypt", "Google", Library, &["org/conscrypt"], &["libconscrypt_jni.so"], &[]),
    s("Lottie", "Airbnb", Library, &["com/airbnb/lottie"]),
    s("EventBus", "greenrobot", Library, &["org/greenrobot/eventbus"]),
    s("ZXing (barcodes)", "ZXing", Library, &["com/google/zxing"]),
    s("LeakCanary (debugging tool)", "Square", Library, &["leakcanary"]),
    s("Timber", "Jake Wharton", Library, &["timber/log"]),
    s("Apache Cordova plugins runtime", "Apache", Library, &["org/apache/cordova"]),
    s("Tor (embedded)", "Tor Project / Guardian Project", Library, &["org/torproject", "info/guardianproject/netcipher"]),
];

/// App frameworks: what the app itself is built with.
pub const FRAMEWORKS: &[Sdk] = &[
    f("Flutter", "Google", Framework, &["io/flutter"], &["libflutter.so"], &["assets/flutter_assets/"]),
    f(
        "React Native",
        "Meta",
        Framework,
        &["com/facebook/react"],
        &["libreactnativejni.so", "libreactnative.so", "libhermes.so", "libjsc.so"],
        &["assets/index.android.bundle"],
    ),
    f("Expo", "Expo", Framework, &["expo/modules", "host/exp/exponent"], &[], &["assets/app.config", "assets/app.manifest"]),
    f("Unity", "Unity", Framework, &["com/unity3d/player"], &["libunity.so"], &["assets/bin/Data/"]),
    f("Unreal Engine", "Epic Games", Framework, &["com/epicgames"], &["libUE4.so", "libUnreal.so"], &[]),
    f(
        "Xamarin / .NET for Android",
        "Microsoft",
        Framework,
        &["mono/android", "mono/java"],
        &["libmonodroid.so", "libxamarin-app.so", "libmonosgen-2.0.so"],
        &["assemblies/"],
    ),
    f("Apache Cordova", "Apache", Framework, &["org/apache/cordova"], &[], &["assets/www/cordova.js"]),
    f("Capacitor", "Ionic", Framework, &["com/getcapacitor"], &[], &["assets/capacitor.config.json"]),
    f("uni-app / DCloud", "DCloud", Framework, &["io/dcloud"], &[], &["assets/data/dcloud_control.xml"]),
    f("Weex", "Alibaba / Apache", Framework, &["com/taobao/weex", "org/apache/weex"], &["libweexcore.so", "libweexjss.so"], &[]),
    f(
        "Cocos",
        "Cocos",
        Framework,
        &["org/cocos2dx", "com/cocos/lib"],
        &["libcocos2dcpp.so", "libcocos2djs.so", "libcocos2dlua.so", "libcocos.so"],
        &[],
    ),
    f("Godot", "Godot Engine", Framework, &["org/godotengine"], &["libgodot_android.so"], &[]),
    f("Qt", "The Qt Company", Framework, &["org/qtproject/qt5", "org/qtproject/qt"], &["libQt5Core*.so", "libQt6Core*.so"], &[]),
    f("libGDX", "libGDX", Framework, &["com/badlogic/gdx"], &["libgdx.so"], &[]),
    f("NativeScript", "OpenJS Foundation", Framework, &["com/tns"], &["libNativeScript.so"], &[]),
    f("Titanium", "TiDev", Framework, &["org/appcelerator"], &["libtitanium.so", "libkroll-v8.so"], &[]),
    f("Kivy / Python for Android", "Kivy", Framework, &["org/kivy"], &["libpython3*.so", "libpython2*.so"], &[]),
    f("Solar2D (Corona)", "Solar2D", Framework, &["com/ansca/corona"], &["libcorona.so"], &[]),
    f("GameMaker", "YoYo Games", Framework, &["com/yoyogames"], &["libyoyo.so"], &[]),
    f("Adobe AIR", "HARMAN", Framework, &["com/adobe/air"], &[], &[]),
    f("B4A (Basic4Android)", "Anywhere Software", Framework, &["anywheresoftware/b4a"], &[], &[]),
    f("MIT App Inventor", "MIT", Framework, &["com/google/appinventor"], &[], &[]),
    f("Tauri", "Tauri", Framework, &["app/tauri"], &[], &[]),
    f("Jetpack Compose", "Google", Framework, &["androidx/compose/runtime"], &[], &[]),
    f("Compose Multiplatform", "JetBrains", Framework, &["org/jetbrains/compose"], &[], &[]),
    f("Kotlin", "JetBrains", Framework, &["kotlin"], &[], &["kotlin/kotlin.kotlin_builtins"]),
];

/// Packers and protectors: tools that hide or wrap the app's real code.
pub const PACKERS: &[Sdk] = &[
    f(
        "360 Jiagu (360 加固)",
        "Qihoo 360",
        Security,
        &["com/stub", "com/qihoo/util"],
        &["libjiagu*.so", "libprotectClass*.so"],
        &["assets/libjiagu.so", "assets/libjiagu_x86.so", "assets/libjiagu_a64.so"],
    ),
    f(
        "Tencent Legu (腾讯乐固)",
        "Tencent",
        Security,
        &["com/tencent/StubShell"],
        &["libshell*.so", "libtup.so", "libtprt.so", "liblegudb.so", "libtosprotection*.so"],
        &["assets/tosversion"],
    ),
    f(
        "Bangcle / SecNeo (梆梆加固)",
        "Bangcle",
        Security,
        &["com/secneo/apkwrapper", "com/SecShell/SecShell", "com/secshell"],
        &["libsecexe*.so", "libsecmain*.so", "libSecShell*.so", "libDexHelper*.so", "libsecpreload*.so"],
        &["assets/secData0.jar"],
    ),
    f(
        "Ijiami (爱加密)",
        "Ijiami",
        Security,
        &["com/shell", "s/h/e/l/l"],
        &["libexec.so", "libexecmain.so", "libijiami*.so"],
        &["assets/ijiami.dat", "assets/ijiami.ajm", "assets/af.bin"],
    ),
    f(
        "Baidu Protect (百度加固)",
        "Baidu",
        Security,
        &["com/baidu/protect"],
        &["libbaiduprotect*.so"],
        &["assets/baiduprotect.jar", "assets/baiduprotect1.jar"],
    ),
    f(
        "Alibaba Jaq (阿里聚安全)",
        "Alibaba",
        Security,
        &["com/ali/mobisecenhance"],
        &["libmobisec*.so", "libzuma.so", "libzumadata.so", "libpreverify1.so"],
        &["assets/aliprotect.dat"],
    ),
    f("NAGA (娜迦)", "NAGA", Security, &[], &["libddog.so", "libfdog.so", "libedog.so", "libchaosvmp.so"], &[]),
    f("NetEase Yidun packer (易盾加固)", "NetEase", Security, &[], &["libnesec.so"], &[]),
    f("Kiwi (几维安全)", "Kiwisec", Security, &["com/kiwisec"], &["libkwscmm.so", "libkwscr.so", "libkwslinker.so"], &[]),
    f(
        "DexProtector",
        "Licel",
        Security,
        &[],
        &["libdexprotector*.so", "libdpboot.so"],
        &["assets/dp.arm-v7.so.dat", "assets/dp.arm-v8.so.dat", "assets/classes.dex.dat"],
    ),
    f("AppSealing", "INKA Entworks", Security, &[], &["libcovault-appsec.so"], &["assets/AppSealing/"]),
    f("Virbox Protector (深思)", "SenseShield", Security, &[], &["libvdog.so", "libv++.so", "libv++_64.so"], &[]),
    f("LIAPP", "Lockin Company", Security, &["com/lockincomp"], &["*LIAPPEgg*"], &["assets/LIAPPClient.sc"]),
    f("APKProtect", "APKProtect", Security, &[], &["libAPKProtect*.so"], &[]),
    f("Tongfudun (通付盾)", "Tongfudun", Security, &[], &["libegis*.so", "libNSaferOnly*.so"], &[]),
    f("NQ Shield (网秦)", "NQ Mobile", Security, &[], &["libnqshield*.so"], &[]),
    f("Dingxiang (顶象)", "Dingxiang", Security, &[], &["libx3g.so"], &[]),
    f("China Mobile packer (移动加固)", "China Mobile", Security, &[], &["libmogosec*.so", "libcmvmp.so"], &[]),
    f("Rising packer (瑞星)", "Rising", Security, &[], &["librsprotect*.so"], &[]),
    f("CNProtect (海云安)", "SecIdea", Security, &[], &["libitsec.so"], &[]),
    f("Promon SHIELD", "Promon", Security, &[], &["libshield.*.so"], &[]),
];

/// Matches a file name against a pattern where `*` stands for any run of characters.
pub fn glob(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else { return false };
    let mut pieces: Vec<&str> = parts.collect();
    let Some(last) = pieces.pop() else { return rest.is_empty() };
    for piece in pieces {
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_patterns() {
        assert!(glob("libjiagu*.so", "libjiagu_a64.so"));
        assert!(glob("libjiagu*.so", "libjiagu.so"));
        assert!(!glob("libjiagu*.so", "libjiagu.so.bak"));
        assert!(glob("libflutter.so", "libflutter.so"));
        assert!(!glob("libflutter.so", "libflutter.so2"));
        assert!(glob("*LIAPPEgg*", "libLIAPPEgg.so"));
        assert!(glob("libshield.*.so", "libshield.abcd.so"));
        assert!(!glob("libshield.*.so", "libshield.so"));
    }

    #[test]
    fn table_is_well_formed() {
        assert!(SDKS.len() >= 150, "{}", SDKS.len());
        for sdk in SDKS.iter().chain(FRAMEWORKS).chain(PACKERS) {
            assert!(!sdk.name.is_empty() && !sdk.vendor.is_empty());
            assert!(!sdk.packages.is_empty() || !sdk.libs.is_empty() || !sdk.files.is_empty(), "{} has no signal", sdk.name);
            for package in sdk.packages {
                assert!(!package.contains('.') && !package.starts_with('/') && !package.ends_with('/'), "{package}");
            }
        }
        let mut names: Vec<&str> = SDKS.iter().chain(FRAMEWORKS).chain(PACKERS).map(|s| s.name).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate names");
    }
}
