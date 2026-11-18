//! Android platform permissions: protection level and a one-line description.
//!
//! The levels follow the platform's `AndroidManifest.xml` (AOSP, Apache-2.0) as of Android 14/15.
//! A level can differ between Android versions, so a classification from this table is derived,
//! not read from the package. The descriptions are our own wording.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Granted at install without asking.
    Normal,
    /// The user must agree at run time.
    Dangerous,
    /// The user must switch it on in a system settings screen (app-op permissions).
    Special,
    /// Only for apps signed with the platform key or preinstalled as privileged.
    Signature,
    /// Not a platform permission this table knows.
    Unknown,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Normal => "normal",
            Level::Dangerous => "dangerous",
            Level::Special => "special",
            Level::Signature => "signature",
            Level::Unknown => "unknown",
        }
    }
}

pub struct Permission {
    pub name: &'static str,
    pub level: Level,
    pub en: &'static str,
    pub zh: &'static str,
}

use Level::{Dangerous as D, Normal as N, Signature as S, Special as A};

const fn p(name: &'static str, level: Level, en: &'static str, zh: &'static str) -> Permission {
    Permission { name, level, en, zh }
}

/// Full permission names, sorted.
pub const PERMISSIONS: &[Permission] = &[
    p("android.permission.ACCEPT_HANDOVER", D, "Continue a call that was started in another app", "接续在其他应用中发起的通话"),
    p("android.permission.ACCESS_ADSERVICES_AD_ID", N, "Read the advertising ID through AdServices", "通过 AdServices 读取广告标识符"),
    p("android.permission.ACCESS_ADSERVICES_ATTRIBUTION", N, "Use the Privacy Sandbox attribution reporting API", "使用隐私沙盒的广告归因报告接口"),
    p("android.permission.ACCESS_ADSERVICES_CUSTOM_AUDIENCE", N, "Use the Privacy Sandbox custom audience API", "使用隐私沙盒的自定义受众接口"),
    p("android.permission.ACCESS_ADSERVICES_TOPICS", N, "Use the Privacy Sandbox topics API", "使用隐私沙盒的兴趣主题接口"),
    p("android.permission.ACCESS_BACKGROUND_LOCATION", D, "Read the device location while the app is in the background", "应用在后台时读取设备位置"),
    p("android.permission.ACCESS_CHECKIN_PROPERTIES", S, "Read and write the check-in database", "读写系统签到数据库"),
    p("android.permission.ACCESS_COARSE_LOCATION", D, "Read the approximate device location", "读取设备的大致位置"),
    p("android.permission.ACCESS_FINE_LOCATION", D, "Read the precise device location", "读取设备的精确位置"),
    p("android.permission.ACCESS_LOCATION_EXTRA_COMMANDS", N, "Send extra commands to location providers", "向位置提供程序发送额外命令"),
    p("android.permission.ACCESS_MEDIA_LOCATION", D, "Read the locations stored in the user's photos and videos", "读取用户照片和视频中保存的拍摄位置"),
    p("android.permission.ACCESS_NETWORK_STATE", N, "See whether and how the device is connected to a network", "查看设备的网络连接状态"),
    p("android.permission.ACCESS_NOTIFICATION_POLICY", A, "Change Do Not Disturb settings", "修改勿扰模式设置"),
    p("android.permission.ACCESS_WIFI_STATE", N, "See Wi-Fi state and the networks in range", "查看 Wi-Fi 状态和周围的网络"),
    p("android.permission.ACCOUNT_MANAGER", S, "Act as the system account manager", "充当系统帐号管理器"),
    p("android.permission.ACTIVITY_RECOGNITION", D, "Recognise physical activity such as walking or driving", "识别步行、驾车等身体活动"),
    p("android.permission.ANSWER_PHONE_CALLS", D, "Answer incoming phone calls", "接听来电"),
    p("android.permission.AUTHENTICATE_ACCOUNTS", N, "Act as an account authenticator (removed in Android 6)", "充当帐号身份验证器（Android 6 起已移除）"),
    p("android.permission.BATTERY_STATS", S, "Read battery usage statistics", "读取电池使用统计"),
    p("android.permission.BIND_ACCESSIBILITY_SERVICE", S, "Lets the system bind an accessibility service, which can read the screen and act for the user", "供系统绑定无障碍服务；该服务可读取屏幕内容并代替用户操作"),
    p("android.permission.BIND_AUTOFILL_SERVICE", S, "Lets the system bind an autofill service", "供系统绑定自动填充服务"),
    p("android.permission.BIND_DEVICE_ADMIN", S, "Lets the system bind a device administrator", "供系统绑定设备管理员"),
    p("android.permission.BIND_INPUT_METHOD", S, "Lets the system bind an input method (keyboard)", "供系统绑定输入法"),
    p("android.permission.BIND_JOB_SERVICE", S, "Lets the system bind a scheduled job service", "供系统绑定计划任务服务"),
    p("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", S, "Lets the system bind a notification listener, which can read all notifications", "供系统绑定通知监听服务；该服务可读取所有通知"),
    p("android.permission.BIND_VPN_SERVICE", S, "Lets the system bind a VPN service, which can see and route network traffic", "供系统绑定 VPN 服务；该服务可查看并转发网络流量"),
    p("android.permission.BLUETOOTH", N, "Connect to paired Bluetooth devices (before Android 12)", "连接已配对的蓝牙设备（Android 12 之前）"),
    p("android.permission.BLUETOOTH_ADMIN", N, "Discover and pair Bluetooth devices (before Android 12)", "发现并配对蓝牙设备（Android 12 之前）"),
    p("android.permission.BLUETOOTH_ADVERTISE", D, "Make the device visible to nearby Bluetooth devices", "让附近的蓝牙设备发现本设备"),
    p("android.permission.BLUETOOTH_CONNECT", D, "Connect to paired Bluetooth devices", "连接已配对的蓝牙设备"),
    p("android.permission.BLUETOOTH_PRIVILEGED", S, "Pair Bluetooth devices without user interaction", "无需用户操作即可配对蓝牙设备"),
    p("android.permission.BLUETOOTH_SCAN", D, "Find nearby Bluetooth devices", "查找附近的蓝牙设备"),
    p("android.permission.BODY_SENSORS", D, "Read body sensors such as heart rate", "读取心率等身体传感器数据"),
    p("android.permission.BODY_SENSORS_BACKGROUND", D, "Read body sensors while the app is in the background", "应用在后台时读取身体传感器数据"),
    p("android.permission.BROADCAST_STICKY", N, "Send sticky broadcasts", "发送持久广播"),
    p("android.permission.CALL_COMPANION_APP", N, "See and control calls through a companion app", "通过配套应用查看和控制通话"),
    p("android.permission.CALL_PHONE", D, "Place phone calls without going through the dialer", "不经拨号界面直接拨打电话"),
    p("android.permission.CALL_PRIVILEGED", S, "Call any number, emergency numbers included", "拨打任意号码，包括紧急号码"),
    p("android.permission.CAMERA", D, "Take pictures and record video", "拍照和录像"),
    p("android.permission.CAPTURE_AUDIO_OUTPUT", S, "Capture the audio the device plays", "捕获设备播放的音频"),
    p("android.permission.CHANGE_COMPONENT_ENABLED_STATE", S, "Enable or disable components of other apps", "启用或停用其他应用的组件"),
    p("android.permission.CHANGE_CONFIGURATION", S, "Change system configuration such as the locale", "修改语言区域等系统配置"),
    p("android.permission.CHANGE_NETWORK_STATE", N, "Change network connectivity", "更改网络连接状态"),
    p("android.permission.CHANGE_WIFI_MULTICAST_STATE", N, "Receive Wi-Fi multicast packets", "接收 Wi-Fi 多播数据包"),
    p("android.permission.CHANGE_WIFI_STATE", N, "Connect to and disconnect from Wi-Fi networks", "连接和断开 Wi-Fi 网络"),
    p("android.permission.CLEAR_APP_CACHE", S, "Clear the caches of all apps", "清除所有应用的缓存"),
    p("android.permission.CREDENTIAL_MANAGER_SET_ORIGIN", N, "Set the origin of a credential request (browsers)", "为凭据请求设置来源（浏览器用）"),
    p("android.permission.DELETE_PACKAGES", S, "Uninstall apps silently", "静默卸载应用"),
    p("android.permission.DETECT_SCREEN_CAPTURE", N, "Be told when the user takes a screenshot of the app", "在用户对应用截屏时得到通知"),
    p("android.permission.DEVICE_POWER", S, "Low-level power management", "底层电源管理"),
    p("android.permission.DISABLE_KEYGUARD", N, "Disable the lock screen while the app is in front", "应用在前台时停用锁屏"),
    p("android.permission.DUMP", S, "Read the internal state of system services", "读取系统服务的内部状态"),
    p("android.permission.ENFORCE_UPDATE_OWNERSHIP", N, "Claim ownership of updates of the apps it installs", "声明对其所安装应用的更新所有权"),
    p("android.permission.EXPAND_STATUS_BAR", N, "Expand or collapse the status bar", "展开或收起状态栏"),
    p("android.permission.FLASHLIGHT", N, "Use the flashlight (removed in Android 6)", "使用闪光灯（Android 6 起已移除）"),
    p("android.permission.FORCE_STOP_PACKAGES", S, "Force other apps to stop", "强行停止其他应用"),
    p("android.permission.FOREGROUND_SERVICE", N, "Run a foreground service", "运行前台服务"),
    p("android.permission.FOREGROUND_SERVICE_CAMERA", N, "Run a foreground service that uses the camera", "运行使用相机的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE", N, "Run a foreground service that talks to connected devices", "运行与外接设备通信的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_DATA_SYNC", N, "Run a foreground service that transfers data", "运行传输数据的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_HEALTH", N, "Run a foreground service for fitness or health tracking", "运行健身或健康记录类前台服务"),
    p("android.permission.FOREGROUND_SERVICE_LOCATION", N, "Run a foreground service that uses location", "运行使用位置的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK", N, "Run a foreground service that plays media", "运行播放媒体的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING", N, "Run a foreground service that processes media", "运行处理媒体的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION", N, "Run a foreground service that captures the screen", "运行捕获屏幕的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_MICROPHONE", N, "Run a foreground service that uses the microphone", "运行使用麦克风的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_PHONE_CALL", N, "Run a foreground service for an ongoing call", "运行用于通话的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING", N, "Run a foreground service that relays messages between devices", "运行在设备间转发消息的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_SPECIAL_USE", N, "Run a foreground service for a use no other type covers", "运行其他类型未涵盖用途的前台服务"),
    p("android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED", N, "Run a foreground service exempt from the usual restrictions", "运行不受常规限制的前台服务"),
    p("android.permission.GET_ACCOUNTS", D, "List the accounts on the device", "列出设备上的帐号"),
    p("android.permission.GET_ACCOUNTS_PRIVILEGED", S, "List all accounts on the device without asking", "无需询问即可列出设备上的全部帐号"),
    p("android.permission.GET_PACKAGE_SIZE", N, "Read how much storage an app uses", "读取应用占用的存储空间"),
    p("android.permission.GET_TASKS", N, "See running tasks (restricted since Android 5)", "查看正在运行的任务（Android 5 起受限）"),
    p("android.permission.GLOBAL_SEARCH", S, "Let global search read a provider's data", "允许全局搜索读取内容提供程序的数据"),
    p("android.permission.HIDE_OVERLAY_WINDOWS", N, "Keep other apps' overlays from showing above its windows", "阻止其他应用的悬浮窗显示在自己的窗口之上"),
    p("android.permission.HIGH_SAMPLING_RATE_SENSORS", N, "Read motion sensors at more than 200 Hz", "以高于 200 Hz 的频率读取运动传感器"),
    p("android.permission.INJECT_EVENTS", S, "Inject touches and key presses into other apps", "向其他应用注入触摸和按键事件"),
    p("android.permission.INSTALL_PACKAGES", S, "Install apps silently", "静默安装应用"),
    p("android.permission.INTERACT_ACROSS_USERS", S, "Interact with other user profiles", "与设备上的其他用户资料交互"),
    p("android.permission.INTERACT_ACROSS_USERS_FULL", S, "Interact fully with other user profiles", "与设备上的其他用户资料完全交互"),
    p("android.permission.INTERNET", N, "Open network connections", "访问网络"),
    p("android.permission.KILL_BACKGROUND_PROCESSES", N, "End the background processes of other apps", "结束其他应用的后台进程"),
    p("android.permission.LOCAL_MAC_ADDRESS", S, "Read the device's real MAC addresses", "读取设备的真实 MAC 地址"),
    p("android.permission.MANAGE_ACCOUNTS", N, "Add and remove accounts (removed in Android 6)", "添加和移除帐号（Android 6 起已移除）"),
    p("android.permission.MANAGE_DOCUMENTS", S, "Manage access to documents, as the system file picker does", "管理文档访问权限（系统文件选择器使用）"),
    p("android.permission.MANAGE_EXTERNAL_STORAGE", A, "Read and write all files on shared storage", "读写共享存储上的所有文件"),
    p("android.permission.MANAGE_MEDIA", A, "Modify or delete media files without asking each time", "无需逐次确认即可修改或删除媒体文件"),
    p("android.permission.MANAGE_OWN_CALLS", N, "Route its own calls through the system", "通过系统管理自身的通话"),
    p("android.permission.MANAGE_USERS", S, "Create, remove and query user profiles", "创建、移除和查询用户资料"),
    p("android.permission.MASTER_CLEAR", S, "Reset the device to factory state", "将设备恢复出厂设置"),
    p("android.permission.MEDIA_CONTENT_CONTROL", S, "See and control what media is playing", "查看和控制正在播放的媒体"),
    p("android.permission.MODIFY_AUDIO_SETTINGS", N, "Change audio settings such as volume and routing", "修改音量、输出通道等音频设置"),
    p("android.permission.MODIFY_PHONE_STATE", S, "Change telephony state, such as turning the radio on or off", "修改电话状态，例如开关移动网络"),
    p("android.permission.MOUNT_UNMOUNT_FILESYSTEMS", S, "Mount and unmount storage", "挂载和卸载存储设备"),
    p("android.permission.NEARBY_WIFI_DEVICES", D, "Find and connect to nearby Wi-Fi devices", "查找并连接附近的 Wi-Fi 设备"),
    p("android.permission.NFC", N, "Communicate over NFC", "使用 NFC 通信"),
    p("android.permission.NFC_TRANSACTION_EVENT", N, "Be told about NFC payment transactions", "接收 NFC 支付交易事件"),
    p("android.permission.PACKAGE_USAGE_STATS", A, "Read which apps are used and for how long", "读取各应用的使用情况和使用时长"),
    p("android.permission.POST_NOTIFICATIONS", D, "Show notifications", "显示通知"),
    p("android.permission.PROCESS_OUTGOING_CALLS", D, "See and redirect outgoing calls", "查看并改拨呼出的电话"),
    p("android.permission.QUERY_ALL_PACKAGES", N, "See every app installed on the device", "查看设备上安装的所有应用"),
    p("android.permission.READ_BASIC_PHONE_STATE", N, "Read basic phone state such as the network type", "读取网络类型等基本电话状态"),
    p("android.permission.READ_CALENDAR", D, "Read calendar events", "读取日历日程"),
    p("android.permission.READ_CALL_LOG", D, "Read the call log", "读取通话记录"),
    p("android.permission.READ_CELL_BROADCASTS", D, "Read cell broadcast (emergency alert) messages", "读取小区广播（紧急警报）消息"),
    p("android.permission.READ_CONTACTS", D, "Read the user's contacts", "读取联系人"),
    p("android.permission.READ_EXTERNAL_STORAGE", D, "Read files on shared storage", "读取共享存储上的文件"),
    p("android.permission.READ_FRAME_BUFFER", S, "Read the screen contents", "读取屏幕内容"),
    p("android.permission.READ_LOGS", S, "Read the system log, which may hold other apps' data", "读取系统日志，其中可能包含其他应用的数据"),
    p("android.permission.READ_MEDIA_AUDIO", D, "Read audio files on shared storage", "读取共享存储上的音频文件"),
    p("android.permission.READ_MEDIA_IMAGES", D, "Read images on shared storage", "读取共享存储上的图片"),
    p("android.permission.READ_MEDIA_VIDEO", D, "Read videos on shared storage", "读取共享存储上的视频"),
    p("android.permission.READ_MEDIA_VISUAL_USER_SELECTED", D, "Read the photos and videos the user picked", "读取用户选定的照片和视频"),
    p("android.permission.READ_PHONE_NUMBERS", D, "Read the device's phone numbers", "读取本机电话号码"),
    p("android.permission.READ_PHONE_STATE", D, "Read phone state: network, ongoing calls and, on old versions, device identifiers", "读取电话状态：网络、通话状态，旧版本上还包括设备标识符"),
    p("android.permission.READ_PRIVILEGED_PHONE_STATE", S, "Read device identifiers such as IMEI", "读取 IMEI 等设备标识符"),
    p("android.permission.READ_SMS", D, "Read text messages", "读取短信"),
    p("android.permission.READ_SYNC_SETTINGS", N, "Read account sync settings", "读取帐号同步设置"),
    p("android.permission.READ_SYNC_STATS", N, "Read account sync statistics", "读取帐号同步统计"),
    p("android.permission.READ_VOICEMAIL", S, "Read voicemails", "读取语音信箱"),
    p("android.permission.REBOOT", S, "Reboot the device", "重启设备"),
    p("android.permission.RECEIVE_BOOT_COMPLETED", N, "Start when the device finishes booting", "开机完成后自动启动"),
    p("android.permission.RECEIVE_MMS", D, "Receive multimedia messages", "接收彩信"),
    p("android.permission.RECEIVE_SMS", D, "Receive text messages", "接收短信"),
    p("android.permission.RECEIVE_WAP_PUSH", D, "Receive WAP push messages", "接收 WAP 推送消息"),
    p("android.permission.RECORD_AUDIO", D, "Record audio with the microphone", "使用麦克风录音"),
    p("android.permission.REORDER_TASKS", N, "Move tasks to the foreground or background", "将任务移到前台或后台"),
    p("android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND", N, "Let a companion-device app run in the background", "允许配套设备应用在后台运行"),
    p("android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND", N, "Let a companion-device app use data in the background", "允许配套设备应用在后台使用流量"),
    p("android.permission.REQUEST_DELETE_PACKAGES", N, "Ask the user to uninstall apps", "请求用户卸载应用"),
    p("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", N, "Ask the user to exempt the app from battery optimisation", "请求用户将应用排除在电池优化之外"),
    p("android.permission.REQUEST_INSTALL_PACKAGES", A, "Ask the user to install other apps", "请求用户安装其他应用"),
    p("android.permission.RESTART_PACKAGES", N, "End background processes (deprecated)", "结束后台进程（已废弃）"),
    p("android.permission.RUN_USER_INITIATED_JOBS", N, "Run long data-transfer jobs the user started", "运行由用户发起的长时间数据传输任务"),
    p("android.permission.SCHEDULE_EXACT_ALARM", A, "Schedule alarms at exact times", "设置精确时间的闹钟/定时任务"),
    p("android.permission.SEND_SMS", D, "Send text messages, which may cost money", "发送短信（可能产生费用）"),
    p("android.permission.SET_ALWAYS_FINISH", S, "Control whether activities are destroyed when left", "控制界面在离开后是否立即销毁"),
    p("android.permission.SET_ANIMATION_SCALE", S, "Change the global animation speed", "修改全局动画速度"),
    p("android.permission.SET_DEBUG_APP", S, "Choose the app to debug", "指定要调试的应用"),
    p("android.permission.SET_PROCESS_LIMIT", S, "Limit the number of running processes", "限制运行中的进程数量"),
    p("android.permission.SET_TIME", S, "Set the system clock", "设置系统时间"),
    p("android.permission.SET_TIME_ZONE", S, "Set the system time zone", "设置系统时区"),
    p("android.permission.SET_WALLPAPER", N, "Set the wallpaper", "设置壁纸"),
    p("android.permission.SET_WALLPAPER_HINTS", N, "Suggest the wallpaper size", "建议壁纸尺寸"),
    p("android.permission.START_ACTIVITIES_FROM_BACKGROUND", S, "Open screens while in the background", "在后台时打开界面"),
    p("android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND", S, "Start foreground services while in the background", "在后台时启动前台服务"),
    p("android.permission.STATUS_BAR", S, "Disable or change the status bar", "停用或修改状态栏"),
    p("android.permission.SYSTEM_ALERT_WINDOW", A, "Draw over other apps", "在其他应用上层显示悬浮窗"),
    p("android.permission.TRANSMIT_IR", N, "Use the infrared transmitter", "使用红外发射器"),
    p("android.permission.TURN_SCREEN_ON", A, "Turn the screen on", "点亮屏幕"),
    p("android.permission.UPDATE_DEVICE_STATS", S, "Change collected device statistics", "修改系统收集的设备统计数据"),
    p("android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION", N, "Update the apps it installed without asking again", "无需再次确认即可更新由它安装的应用"),
    p("android.permission.USE_BIOMETRIC", N, "Use fingerprint, face or other biometric hardware", "使用指纹、人脸等生物识别硬件"),
    p("android.permission.USE_CREDENTIALS", N, "Use account credentials (removed in Android 6)", "使用帐号凭据（Android 6 起已移除）"),
    p("android.permission.USE_EXACT_ALARM", N, "Schedule alarms at exact times (clock and calendar apps)", "设置精确时间的闹钟（时钟、日历类应用）"),
    p("android.permission.USE_FINGERPRINT", N, "Use the fingerprint sensor", "使用指纹传感器"),
    p("android.permission.USE_FULL_SCREEN_INTENT", A, "Show full-screen notifications such as incoming calls", "显示来电等全屏通知"),
    p("android.permission.USE_SIP", D, "Make and receive SIP (internet) calls", "拨打和接听 SIP 网络电话"),
    p("android.permission.UWB_RANGING", D, "Measure the distance to nearby ultra-wideband devices", "测量与附近超宽带设备的距离"),
    p("android.permission.VIBRATE", N, "Vibrate the device", "控制振动"),
    p("android.permission.WAKE_LOCK", N, "Keep the device from sleeping", "阻止设备休眠"),
    p("android.permission.WRITE_APN_SETTINGS", S, "Change mobile network access point settings", "修改移动网络接入点设置"),
    p("android.permission.WRITE_CALENDAR", D, "Add and change calendar events", "添加和修改日历日程"),
    p("android.permission.WRITE_CALL_LOG", D, "Change the call log", "修改通话记录"),
    p("android.permission.WRITE_CONTACTS", D, "Add and change contacts", "添加和修改联系人"),
    p("android.permission.WRITE_EXTERNAL_STORAGE", D, "Write files on shared storage", "写入共享存储上的文件"),
    p("android.permission.WRITE_SECURE_SETTINGS", S, "Change secure system settings", "修改受保护的系统设置"),
    p("android.permission.WRITE_SETTINGS", A, "Change system settings", "修改系统设置"),
    p("android.permission.WRITE_SYNC_SETTINGS", N, "Change account sync settings", "修改帐号同步设置"),
    p("android.permission.WRITE_VOICEMAIL", S, "Change voicemails", "修改语音信箱"),
    p("com.android.alarm.permission.SET_ALARM", N, "Set an alarm in the clock app", "在时钟应用中设置闹钟"),
    p("com.android.launcher.permission.INSTALL_SHORTCUT", N, "Add shortcuts to the home screen", "在主屏幕添加快捷方式"),
    p("com.android.voicemail.permission.ADD_VOICEMAIL", D, "Add voicemails to the system", "向系统添加语音信箱留言"),
];

/// Looks a permission up by its full name.
pub fn lookup(name: &str) -> Option<&'static Permission> {
    PERMISSIONS.binary_search_by(|p| p.name.cmp(name)).ok().map(|i| &PERMISSIONS[i])
}

/// Well-known permissions defined by other apps; all are granted without a prompt.
pub const THIRD_PARTY: &[(&str, &str, &str)] = &[
    ("com.android.vending.BILLING", "Use Google Play billing", "使用 Google Play 结算"),
    ("com.android.vending.CHECK_LICENSE", "Check the Google Play licence", "校验 Google Play 许可"),
    ("com.google.android.c2dm.permission.RECEIVE", "Receive push messages through Google (FCM)", "通过 Google（FCM）接收推送消息"),
    ("com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE", "Read the Google Play install referrer", "读取 Google Play 安装来源信息"),
    ("com.google.android.gms.permission.ACTIVITY_RECOGNITION", "Recognise physical activity through Google Play services", "通过 Google Play 服务识别身体活动"),
    ("com.google.android.gms.permission.AD_ID", "Read the Google advertising ID", "读取 Google 广告标识符"),
    ("com.google.android.providers.gsf.permission.READ_GSERVICES", "Read Google services configuration", "读取 Google 服务配置"),
];

pub fn third_party(name: &str) -> Option<(&'static str, &'static str)> {
    THIRD_PARTY.iter().find(|(n, _, _)| *n == name).map(|(_, en, zh)| (*en, *zh))
}

/// The base protection level in a `<permission android:protectionLevel>` value.
pub fn declared_level(value: i64) -> Level {
    match value & 0x0f {
        0 => Level::Normal,
        1 => Level::Dangerous,
        // 2 signature, 3 signatureOrSystem, 4 internal
        2..=4 => Level::Signature,
        _ => Level::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(PERMISSIONS.windows(2).all(|w| w[0].name < w[1].name), "table must stay sorted for binary search");
        assert!(PERMISSIONS.iter().all(|p| !p.en.is_empty() && !p.zh.is_empty()));
    }

    #[test]
    fn levels_of_well_known_permissions() {
        assert_eq!(lookup("android.permission.CAMERA").map(|p| p.level), Some(Level::Dangerous));
        assert_eq!(lookup("android.permission.INTERNET").map(|p| p.level), Some(Level::Normal));
        assert_eq!(lookup("android.permission.SYSTEM_ALERT_WINDOW").map(|p| p.level), Some(Level::Special));
        assert_eq!(lookup("android.permission.INSTALL_PACKAGES").map(|p| p.level), Some(Level::Signature));
        assert!(lookup("com.example.X").is_none());
        assert_eq!(declared_level(0x12), Level::Signature);
        assert_eq!(declared_level(1), Level::Dangerous);
    }
}
