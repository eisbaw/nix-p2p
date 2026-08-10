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
//!   (`NarHashKey`, `Blake3Digest`, `Claim`, `StorePath`), OR is one of the
//!   WRAPPER types that carries such a collection inside it (`BatchHoldResponse`)
//!   then the PARAMETERS must mention an identity type or a KEY-BEARING QUERY
//!   type (`HoldQuery`, `BatchHoldQuery`).
//!
//! In other words: plural holdings out require named keys in. A `fn all_keys(&self)
//! -> Vec<NarHashKey>` fails; `fn resolve_many(&self, keys: &[NarHashKey]) ->
//! Vec<Option<Claim>>` passes, because every element of its result is about a key
//! the caller supplied; `fn answer_batch(&self, q: &BatchHoldQuery) ->
//! BatchHoldResponse` passes, because a `BatchHoldQuery` IS a list of named keys.
//!
//! ## What this file got wrong the first time, and what fixed it
//!
//! A cross-model review defeated the first version of this guard twice over:
//!
//!   * It matched only on CONTAINER return types, so a method returning the
//!     wrapper `BatchHoldResponse` - which contains a whole vector of holdings -
//!     was invisible. A no-argument `fn everything(&self) -> BatchHoldResponse`
//!     dumping every derived BLAKE3 passed both tests. Hence `PLURAL_WRAPPERS`.
//!   * `ALLOWED` matched a bare function NAME across all files, so adding
//!     `fn load(&self) -> Vec<NarHashKey>` to a DIFFERENT module inherited an
//!     exemption written for `IndexStore::load`. Hence `(file, name)` pairs.
//!
//! The parser was also silently mis-reading `pub(crate) fn` (it split the
//! parameter list at the paren in `pub(crate)`), so those signatures were checked
//! as garbage. `the_parser_reads_the_shapes_it_claims_to` pins the shapes.
//!
//! ## Honest limits of this guard
//!
//!   * ITS SCOPE IS THREE MODULES: `claim`, `availability`, `discovery`. A listing
//!     method added to any other module - `catalog`, `source`, `transport_iroh` -
//!     is outside this rule entirely. Those modules do not answer peer messages
//!     today, which is exactly the assumption that would have to be re-checked
//!     before one of them did.
//!   * It is a TYPE-SHAPE rule, not a proof. A method could take one key and
//!     return a hundred unrelated claims and pass here. That specific hole is
//!     covered behaviourally (`discovery.rs::a_batch_never_reveals_a_holding_the_asker_did_not_name`,
//!     which asserts the answer count equals the asked count and that no unasked
//!     key appears on the wire). The two together are what the invariant rests on.
//!   * It reads the source as text. A macro-generated method would be invisible to
//!     it. None of these modules generate methods by macro today.
//!   * `WRAPPER` membership is a hand-maintained list. A NEW type that carries a
//!     collection of holdings must be added to it; nothing detects that
//!     automatically. `a_new_wrapper_type_must_be_declared` states the obligation
//!     in a place a reader of a failing test will see it.

const SOURCES: &[(&str, &str)] = &[
    ("claim.rs", include_str!("../src/claim.rs")),
    ("availability.rs", include_str!("../src/availability.rs")),
    ("discovery.rs", include_str!("../src/discovery.rs")),
];

/// Identity types whose PLURAL return is a potential holdings listing.
const IDENTITY_TYPES: &[&str] = &["NarHashKey", "Blake3Digest", "Claim", "StorePath"];

/// Types that CARRY a collection of holdings inside them, so returning one bare -
/// with no container in sight - is just as much a listing as returning a `Vec`.
/// This is the hole a cross-model review walked straight through.
const PLURAL_WRAPPERS: &[&str] = &["BatchHoldResponse"];

/// Parameter types that constitute "the caller named the keys". The identity types
/// themselves, plus the QUERY types - which exist precisely to carry a caller's
/// named keys and are how a wire-facing responder receives them.
const KEY_BEARING_PARAMS: &[&str] = &["NarHashKey", "Blake3Digest", "HoldQuery", "BatchHoldQuery"];

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
///
/// SCOPED BY FILE, not by bare name: an exemption is an argument about ONE
/// function, and a bare name would silently hand that argument to any same-named
/// function added anywhere in the three modules.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "availability.rs",
        "load",
        "IndexStore::load reads THIS node's own persisted registrations off local \
         disk at startup. It is not reachable from any wire message - no peer \
         input can cause it to be called - and a node is obviously allowed to \
         know its own index.",
    ),
    (
        "availability.rs",
        "save",
        "IndexStore::save is the write direction of the same local persistence \
         seam; it takes the entries as an argument.",
    ),
    (
        "claim.rs",
        "decode_batch_hold_response",
        "A CODEC entry point, not a producer of holdings: it turns bytes this node \
         RECEIVED into the typed answer to a query this node ITSELF sent, and it \
         is handed the asked count so it can reject any other length. It cannot \
         invent a holding - everything in its output came off the wire, and the \
         wire form has no field in which a key can be named.",
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

        // Split at the parameter list's matching close paren - searching from AFTER
        // the `fn` keyword. Searching from the start of the line instead finds the
        // paren in `pub(crate)`, which made every `pub(crate) fn` parse as a
        // function named "" with parameters "crate" and the whole real signature as
        // its return type. That is not a cosmetic bug: such a signature is checked
        // against the wrong text entirely.
        let Some(fn_at) = sig.find("fn ") else {
            continue;
        };
        let Some(open) = sig[fn_at..].find('(').map(|at| at + fn_at) else {
            continue;
        };
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

        let name = sig[fn_at + 3..open]
            .trim()
            .split('<')
            .next()
            .unwrap_or("")
            .to_string();
        out.push(Signature {
            file,
            name,
            params: sig[open + 1..close].to_string(),
            ret: sig[close + 1..].to_string(),
        });
    }
    out
}

/// Does `text` name any of `types` as a WHOLE word? (Substring matching would see
/// `Claim` inside `ClaimCodecError` and flag every encoder in the module.)
fn mentions(text: &str, types: &[&str]) -> bool {
    let bytes = text.as_bytes();
    let boundary = |b: u8| !b.is_ascii_alphanumeric() && b != b'_';
    types.iter().any(|ty| {
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
fn returns_plural_container(ret: &str) -> bool {
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
            if mentions(&ret[open_at + 1..end], IDENTITY_TYPES) {
                return true;
            }
        }
    }
    false
}

/// Does `ret` yield plural holdings AT ALL - as a container, or wrapped in a type
/// that carries a collection of them?
fn returns_plural_identity(ret: &str) -> bool {
    returns_plural_container(ret) || mentions(ret, PLURAL_WRAPPERS)
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
            if ALLOWED
                .iter()
                .any(|(allowed_file, name, _)| *allowed_file == *file && *name == sig.name)
            {
                continue;
            }
            if !mentions(&sig.params, KEY_BEARING_PARAMS) {
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
    // ...and it must SEE the functions that really do return plural holdings, by
    // name - including the WRAPPER-returning ones, which the first version of this
    // guard could not see at all.
    for expected in ["load", "resolve_many", "answer_batch", "query_batch"] {
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
        !mentions(&sigs[0].params, KEY_BEARING_PARAMS),
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
        mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "a caller-supplied key list is exactly what makes a plural answer legitimate"
    );
}

#[test]
fn the_guard_bites_on_an_enumeration_hidden_in_a_wrapper_type() {
    // THE bypass a cross-model review actually built: no container in the return
    // type at all, so the container rule sees nothing - but `BatchHoldResponse`
    // carries a whole vector of holdings, and this method takes no key.
    let hostile = r#"
        impl AvailabilityIndex {
            pub fn everything_i_hold(&self) -> BatchHoldResponse {
                let answers = self.by_digest.lock().unwrap().keys()
                    .map(|blake3| BatchHoldAnswer::Have { blake3: *blake3, offer_indices: vec![] })
                    .collect();
                BatchHoldResponse { schema_version: 1, offers: vec![], answers }
            }
        }
    "#;
    let sigs = signatures("hostile.rs", hostile);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].name, "everything_i_hold");
    assert!(
        !returns_plural_container(&sigs[0].ret),
        "the container rule alone is blind to this - that is the point"
    );
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "a bare BatchHoldResponse return must count as plural holdings"
    );
    assert!(
        !mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "it is handed no keys, so the rule must reject it"
    );

    // The honest responder has the SAME return type and passes, because its
    // parameter is the asker's own list of named keys.
    let legitimate = r#"
        impl AvailabilityIndex {
            pub fn answer_batch(&self, query: &BatchHoldQuery) -> BatchHoldResponse {
            }
        }
    "#;
    let sigs = signatures("legit.rs", legitimate);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "a BatchHoldQuery IS the caller's named keys"
    );
}

#[test]
fn an_exemption_does_not_leak_across_files() {
    // `load` is exempt in availability.rs (local persistence). The SAME name in
    // discovery.rs - which is peer-facing - must NOT inherit that argument.
    let exempt = ALLOWED
        .iter()
        .any(|(file, name, _)| *file == "availability.rs" && *name == "load");
    assert!(exempt, "the availability.rs::load exemption must exist");
    let leaked = ALLOWED
        .iter()
        .any(|(file, name, _)| *file == "discovery.rs" && *name == "load");
    assert!(
        !leaked,
        "an exemption is an argument about ONE function in ONE file"
    );

    // And the rule as applied agrees: a discovery.rs `load` returning a key list
    // is a violation, exactly as if it had any other name.
    let hostile = r#"
        impl DirectDiscovery {
            pub fn load(&self) -> Vec<NarHashKey> {
            }
        }
    "#;
    let sigs = signatures("discovery.rs", hostile);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        !ALLOWED
            .iter()
            .any(|(file, name, _)| *file == "discovery.rs" && *name == sigs[0].name),
        "discovery.rs::load must not be exempt"
    );
}

#[test]
fn the_parser_reads_the_shapes_it_claims_to() {
    // A mis-parsed signature is checked against the wrong TEXT, which is a silent
    // pass, not a loud failure. `pub(crate) fn` used to split at the paren in
    // `pub(crate)`: name "", params "crate", return type = the entire real
    // signature. Every `pub(crate)` function in three modules was unchecked.
    let src = r#"
        pub(crate) fn check_batch_keys(keys: &[NarHashKey]) -> Result<(), ClaimCodecError> {
        }
        pub async fn resolve_many(&self, keys: &[NarHashKey]) -> Vec<Option<Claim>> {
        }
        fn helper(a: usize) -> usize {
        }
    "#;
    let sigs = signatures("probe.rs", src);
    let names: Vec<&str> = sigs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["check_batch_keys", "resolve_many", "helper"]);
    assert_eq!(sigs[0].params.trim(), "keys: &[NarHashKey]");
    assert!(sigs[0].ret.contains("Result<(), ClaimCodecError>"));
    assert!(
        !returns_plural_identity(&sigs[0].ret),
        "a Result<(), _> return holds no holdings"
    );
    assert!(returns_plural_identity(&sigs[1].ret));
}

#[test]
fn a_new_wrapper_type_must_be_declared() {
    // This test exists to be READ, by whoever adds the next response type. The
    // wrapper list is hand-maintained: a new type that carries a collection of
    // holdings is invisible to this guard until it is named here. There is no
    // automatic detection, and pretending otherwise would be the vacuous-oracle
    // failure one level up.
    assert!(
        PLURAL_WRAPPERS.contains(&"BatchHoldResponse"),
        "the batch response carries a vector of holdings and must be declared"
    );
    assert_eq!(
        PLURAL_WRAPPERS.len(),
        1,
        "if you added a wrapper type, add it here AND to PLURAL_WRAPPERS - and if \
         you added a response type that carries holdings and did NOT add it, this \
         guard does not see it at all"
    );
}
