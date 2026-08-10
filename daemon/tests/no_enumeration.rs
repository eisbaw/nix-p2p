//! The no-enumeration invariant as a STRUCTURAL guard over the source (task-91).
//!
//! ## Why a source guard and not a behavioural test
//!
//! The PRD privacy invariant is "a peer cannot be asked what it holds". Every
//! other test in this repo proves a POSITIVE - that some specific probe answers
//! only about the keys it named. But the invariant is a statement about ABSENCE:
//! *no* method anywhere returns holdings the caller did not name. No amount of
//! calling the API proves that a listing method does not exist somewhere else in
//! it; only looking at the whole API surface does.
//!
//! That matters now more than before, because task-91's batch answer is the first
//! message in this system whose SHAPE resembles a listing (a vector of yes/nos).
//! It is not one - it is positional over keys the asker supplied - but "it is not
//! one because of how we currently populate it" is a property that a later, well
//! meaning change could quietly remove. This guard makes the property a rule about
//! the API's TYPES: a method may return a collection of holdings only if it was
//! handed the keys those holdings are about.
//!
//! ## The rule, precisely
//!
//! For every function signature in the three modules that make up the discovery
//! surface (`claim`, `availability`, `discovery`):
//!
//!   if the RETURN type contains a multi-valued container of an identity type
//!   (`NarHashKey`, `Blake3Digest`, `Claim`, `StorePath`)
//!   then the PARAMETERS must mention `NarHashKey` or `Blake3Digest`.
//!
//! In other words: plural holdings out require named keys in. A `fn all_keys(&self)
//! -> Vec<NarHashKey>` fails; `fn resolve_many(&self, keys: &[NarHashKey]) ->
//! Vec<Option<Claim>>` passes, because every element of its result is about a key
//! the caller supplied.
//!
//! ## Honest limits of this guard
//!
//!   * It is a TYPE-SHAPE rule, not a proof. A method could take one key and
//!     return a hundred unrelated claims and pass here. That specific hole is
//!     covered behaviourally (`discovery.rs::a_batch_never_reveals_a_holding_the_asker_did_not_name`,
//!     which asserts the answer count equals the asked count and that no unasked
//!     key appears on the wire). The two together are what the invariant rests on.
//!   * It reads the source as text. A macro-generated method would be invisible to
//!     it. None of these modules generate methods by macro today.

const SOURCES: &[(&str, &str)] = &[
    ("claim.rs", include_str!("../src/claim.rs")),
    ("availability.rs", include_str!("../src/availability.rs")),
    ("discovery.rs", include_str!("../src/discovery.rs")),
];

/// Identity types whose PLURAL return is a potential holdings listing.
const IDENTITY_TYPES: &[&str] = &["NarHashKey", "Blake3Digest", "Claim", "StorePath"];

/// Container shapes that make a return value plural.
const CONTAINERS: &[&str] = &[
    "Vec<",
    "HashMap<",
    "HashSet<",
    "BTreeMap<",
    "&[",
    "Iterator<",
];

/// Functions exempted from the rule, each with the reason it is not a peer-facing
/// listing. Keeping this list SHORT and justified is the point: an entry here is a
/// claim that the method cannot be reached from a wire message.
const ALLOWED: &[(&str, &str)] = &[
    (
        "load",
        "IndexStore::load reads THIS node's own persisted registrations off local \
         disk at startup. It is not reachable from any wire message - no peer \
         input can cause it to be called - and a node is obviously allowed to \
         know its own index.",
    ),
    (
        "save",
        "IndexStore::save is the write direction of the same local persistence \
         seam; it takes the entries as an argument.",
    ),
];

/// One parsed signature: the name, the parameter list, and the return type.
#[derive(Debug)]
struct Signature {
    file: &'static str,
    name: String,
    params: String,
    ret: String,
}

/// Extract every function signature from `src`. Deliberately simple: doc comments
/// and line comments are stripped first, then each `fn` is accumulated up to the
/// start of its body.
fn signatures(file: &'static str, src: &str) -> Vec<Signature> {
    let code: Vec<&str> = src
        .lines()
        // The rule is about the API, so the in-file `#[cfg(test)]` module is not
        // part of it - a test helper that builds a Vec of keys is not a peer-facing
        // listing.
        .take_while(|line| line.trim() != "#[cfg(test)]")
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect();

    let mut out = Vec::new();
    let mut i = 0;
    while i < code.len() {
        let line = code[i];
        let is_fn = line.starts_with("fn ")
            || line.starts_with("pub fn ")
            || line.starts_with("async fn ")
            || line.starts_with("pub async fn ")
            || line.starts_with("pub(crate) fn ");
        if !is_fn {
            i += 1;
            continue;
        }
        // Accumulate until the body opens or the (trait) declaration ends.
        let mut sig = String::new();
        while i < code.len() {
            sig.push_str(code[i]);
            sig.push(' ');
            if code[i].ends_with('{') || code[i].ends_with(';') {
                break;
            }
            i += 1;
        }
        i += 1;

        // Split at the parameter list's matching close paren.
        let Some(open) = sig.find('(') else { continue };
        let mut depth = 0usize;
        let mut close = None;
        for (idx, ch) in sig.char_indices().skip(open) {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { continue };

        let name = sig[..open]
            .rsplit_once("fn ")
            .map(|(_, rest)| rest.trim().split('<').next().unwrap_or("").to_string())
            .unwrap_or_default();
        out.push(Signature {
            file,
            name,
            params: sig[open + 1..close].to_string(),
            ret: sig[close + 1..].to_string(),
        });
    }
    out
}

/// Does `text` name an identity type as a WHOLE word? (Substring matching would
/// see `Claim` inside `ClaimCodecError` and flag every encoder in the module.)
fn contains_identity(text: &str) -> bool {
    let bytes = text.as_bytes();
    let boundary = |b: u8| !b.is_ascii_alphanumeric() && b != b'_';
    IDENTITY_TYPES.iter().any(|ty| {
        text.match_indices(ty).any(|(at, _)| {
            let before = at == 0 || boundary(bytes[at - 1]);
            let end = at + ty.len();
            let after = end >= bytes.len() || boundary(bytes[end]);
            before && after
        })
    })
}

/// Does `ret` return a PLURAL container of an identity type? Only the container's
/// own type ARGUMENT counts, so `Result<Vec<u8>, ClaimCodecError>` is not a
/// holdings listing while `Result<Vec<NarHashKey>, _>` is.
fn returns_plural_identity(ret: &str) -> bool {
    for container in CONTAINERS {
        for (at, _) in ret.match_indices(container) {
            let open_at = at + container.len() - 1;
            let open = ret.as_bytes()[open_at] as char;
            let close = if open == '[' { ']' } else { '>' };
            let mut depth = 0usize;
            let mut end = ret.len();
            for (idx, ch) in ret.char_indices().skip(open_at) {
                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        end = idx;
                        break;
                    }
                }
            }
            if contains_identity(&ret[open_at + 1..end]) {
                return true;
            }
        }
    }
    false
}

#[test]
fn no_function_returns_plural_holdings_it_was_not_given() {
    let mut violations = Vec::new();
    let mut checked = 0usize;
    let mut plural_returns: Vec<String> = Vec::new();

    for (file, src) in SOURCES {
        for sig in signatures(file, src) {
            checked += 1;
            if !returns_plural_identity(&sig.ret) {
                continue;
            }
            plural_returns.push(sig.name.clone());
            if ALLOWED.iter().any(|(name, _)| *name == sig.name) {
                continue;
            }
            let named_keys =
                sig.params.contains("NarHashKey") || sig.params.contains("Blake3Digest");
            if !named_keys {
                violations.push(format!(
                    "{}::{} returns plural holdings ({}) without being handed any key \
                     - that is an enumeration API",
                    sig.file,
                    sig.name,
                    sig.ret.trim().trim_end_matches('{').trim()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "no-enumeration violations:\n  {}",
        violations.join("\n  ")
    );

    // The guard must actually be LOOKING at something. Without these, a parser
    // that silently matched nothing would report a clean bill of health forever -
    // the exact vacuous-oracle failure this repo has shipped before.
    assert!(
        // A floor, not a census: the three modules define ~95 non-test functions
        // today, and a parser that had stopped working would report a handful.
        checked > 60,
        "the signature parser found only {checked} functions across {} files; it is \
         not parsing the sources",
        SOURCES.len()
    );
    // ...and it must SEE the two functions that really do return plural holdings,
    // by name. A rule that matched nothing would otherwise report a clean bill of
    // health forever.
    for expected in ["load", "resolve_many"] {
        assert!(
            plural_returns.iter().any(|name| name == expected),
            "the rule did not even notice `{expected}`, which does return plural \
             holdings; it is matching nothing. Saw: {plural_returns:?}"
        );
    }
}

#[test]
fn the_guard_bites_on_a_synthetic_enumeration_api() {
    // Proves the rule is not vacuous by running it against source text that
    // CONTAINS an enumeration method. If this test ever passes-by-not-detecting,
    // the guard above is decorative.
    let hostile = r#"
        impl AvailabilityIndex {
            pub fn all_holdings(&self) -> Vec<NarHashKey> {
                self.entries.lock().unwrap().keys().copied().collect()
            }
        }
    "#;
    let sigs = signatures("hostile.rs", hostile);
    assert_eq!(sigs.len(), 1, "the parser must find the hostile method");
    assert_eq!(sigs[0].name, "all_holdings");
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "a Vec<NarHashKey> return must be recognised as plural holdings"
    );
    assert!(
        !sigs[0].params.contains("NarHashKey"),
        "and it takes no key - so the rule must reject it"
    );

    // The same shape WITH the keys handed in is legitimate and must pass.
    let legitimate = r#"
        impl AvailabilityIndex {
            pub fn holdings_for(&self, keys: &[NarHashKey]) -> Vec<Option<Claim>> {
                keys.iter().map(|k| self.claim(k)).collect()
            }
        }
    "#;
    let sigs = signatures("legit.rs", legitimate);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        sigs[0].params.contains("NarHashKey"),
        "a caller-supplied key list is exactly what makes a plural answer legitimate"
    );
}
