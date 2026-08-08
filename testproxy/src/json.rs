//! A tiny hand-rolled JSON writer for the log and stats endpoints.
//!
//! The fixture is deliberately dependency-free (see the crate docs): pulling in
//! `serde_json` would be a third-party crate the daemon almost certainly also
//! uses, and while the independence gate would tolerate a pure-data crate, the
//! cleanest possible "independent witness" is one whose whole dependency set is
//! `std`. The output here is small and fully under our control, so a correct
//! string escaper plus manual object assembly is all it takes.

/// Escape a string into a JSON string literal, including the surrounding
/// quotes. Handles the control characters JSON requires escaped; everything
/// else (including UTF-8) passes through, which is valid JSON.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Assembles a single JSON object from `"key": value` fragments. The caller is
/// responsible for producing already-serialised values (via [`quote`] for
/// strings, or plain number/bool literals), which keeps this a mechanical join
/// rather than a general value model we do not need.
#[derive(Default)]
pub struct Object {
    fields: Vec<String>,
}

impl Object {
    pub fn new() -> Self {
        Object::default()
    }

    /// Add a string-valued field.
    pub fn str(mut self, key: &str, value: &str) -> Self {
        self.fields.push(format!("{}:{}", quote(key), quote(value)));
        self
    }

    /// Add a field whose value is an already-serialised JSON fragment
    /// (a number, a bool, `null`, or a nested object/array).
    pub fn raw(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.fields.push(format!("{}:{}", quote(key), value));
        self
    }

    pub fn finish(self) -> String {
        format!("{{{}}}", self.fields.join(","))
    }
}

/// Join already-serialised element strings into a JSON array.
pub fn array<I: IntoIterator<Item = String>>(elements: I) -> String {
    let joined: Vec<String> = elements.into_iter().collect();
    format!("[{}]", joined.join(","))
}

/// Serialise an `Option<f64>` as a JSON number or `null`.
pub fn opt_f64(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("{v:.3}"),
        None => "null".to_string(),
    }
}

/// Serialise an `Option<&str>` as a JSON string or `null`.
pub fn opt_str(value: Option<&str>) -> String {
    match value {
        Some(v) => quote(v),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_escape_the_dangerous_characters() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(quote("\u{01}"), "\"\\u0001\"");
    }

    #[test]
    fn object_and_array_assemble() {
        let obj = Object::new()
            .str("k", "v")
            .raw("n", 42)
            .raw("b", true)
            .finish();
        assert_eq!(obj, "{\"k\":\"v\",\"n\":42,\"b\":true}");
        assert_eq!(array(["1".into(), "2".into()]), "[1,2]");
    }

    #[test]
    fn options_serialise_as_number_or_null() {
        assert_eq!(opt_f64(Some(1.5)), "1.500");
        assert_eq!(opt_f64(None), "null");
        assert_eq!(opt_str(Some("x")), "\"x\"");
        assert_eq!(opt_str(None), "null");
    }
}
