//! The element tree every manifest source is decoded into: binary XML from an APK, protobuf XML
//! from an app bundle, or text XML from a decoded folder.

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// A typed attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    /// `@0x7f…`: a reference to a resource.
    Ref(u32),
    /// `?0x…`: a reference to a theme attribute.
    AttrRef(u32),
    Int(i32),
    Hex(u32),
    Bool(bool),
    Float(f32),
    /// Any other typed value: the resource data type and its raw data.
    Other { data_type: u8, data: u32 },
    Null,
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The value as a boolean, the way Android's `TypedArray.getBoolean` reads it.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::Int(i) => Some(*i != 0),
            Value::Hex(h) => Some(*h != 0),
            Value::Str(text) => match text.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(i64::from(*i)),
            Value::Hex(h) => Some(i64::from(*h)),
            Value::Str(text) => {
                let text = text.trim();
                match text.strip_prefix("0x") {
                    Some(hex) => i64::from_str_radix(hex, 16).ok(),
                    None => text.parse().ok(),
                }
            }
            _ => None,
        }
    }

    pub fn as_ref_id(&self) -> Option<u32> {
        match self {
            Value::Ref(id) => Some(*id),
            _ => None,
        }
    }

    /// The value as text for display: strings as they are, references as `@0x…`.
    pub fn display(&self) -> String {
        match self {
            Value::Str(text) => text.clone(),
            Value::Ref(id) => format!("@0x{id:08x}"),
            Value::AttrRef(id) => format!("?0x{id:08x}"),
            Value::Int(i) => i.to_string(),
            Value::Hex(h) => format!("0x{h:x}"),
            Value::Bool(b) => b.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Other { data_type, data } => format!("(type 0x{data_type:02x}) 0x{data:08x}"),
            Value::Null => String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub ns: Option<String>,
    /// The name Android uses: from the resource id when it has one, else as written.
    pub name: String,
    /// The name as written in the file.
    pub raw_name: String,
    pub res_id: Option<u32>,
    pub value: Value,
    /// The raw string the file keeps beside a typed value, when present.
    pub raw: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    pub ns: Option<String>,
    pub name: String,
    pub attrs: Vec<Attr>,
    pub children: Vec<Element>,
    /// Character data directly inside the element, concatenated.
    pub text: String,
    /// Byte offset of the element's start in the source file, when the source has one.
    pub offset: Option<u64>,
}

impl Element {
    /// The `android:` attribute `name`. Falls back to an attribute of that name in no namespace,
    /// which Android does not accept but which shows what the author meant.
    pub fn android(&self, name: &str) -> Option<&Attr> {
        self.attrs
            .iter()
            .find(|a| a.name == name && (a.res_id.is_some() || a.ns.as_deref() == Some(ANDROID_NS)))
            .or_else(|| self.attrs.iter().find(|a| a.name == name && a.ns.as_deref() == Some(ANDROID_NS)))
    }

    /// The attribute `name` that has no namespace, such as `package` on `<manifest>`.
    pub fn plain(&self, name: &str) -> Option<&Attr> {
        self.attrs.iter().find(|a| a.name == name && a.ns.as_deref().is_none_or(str::is_empty) && a.res_id.is_none())
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }
}

/// A decoded document.
#[derive(Debug, Clone, Default)]
pub struct Document {
    pub root: Option<Element>,
    /// Things a well-formed file would not have; each is a short fixed phrase.
    pub anomalies: Vec<String>,
    /// True when decoding stopped early at a limit.
    pub truncated: bool,
}
