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
//! For every function signature in the five modules that make up the discovery
//! surface (`claim`, `availability`, `supply_catalog`, `discovery`, and
//! `transport_iroh`):
//!
//!   if the RETURN type contains a multi-valued container of an identity type
//!   (`NarHashKey`, `Blake3Digest`, `Claim`, `StorePath`, `BatchHoldAnswer`,
//!   `PersistedRegistration`), OR is one of the WRAPPER types that carries such a
//!   collection inside it (`BatchHoldResponse`)
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
//!   * ITS SCOPE IS FIVE MODULES: `claim`, `availability`, `supply_catalog`, `discovery` and
//!     `transport_iroh`. A listing added to any OTHER module is invisible to it.
//!     The previous note justified the narrower scope by saying the unscanned
//!     modules "do not answer peer messages today". That was FALSE of
//!     `transport_iroh`, which is precisely the module that accepts peer
//!     connections and probes the inert supply catalog - and whose own docs
//!     anticipate an index that enumerates a node's held NARs (task-50). It is
//!     now in scope. The remaining unscanned modules are the HTTP/proxy and
//!     fixture surfaces; that is a real limit, stated rather than argued away.
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
    ("claim.rs", include_str!("../../daemon-core/src/claim.rs")),
    (
        "availability.rs",
        include_str!("../../daemon-core/src/availability.rs"),
    ),
    (
        "supply_catalog.rs",
        include_str!("../../daemon-core/src/supply_catalog.rs"),
    ),
    (
        "discovery.rs",
        include_str!("../../daemon-core/src/discovery.rs"),
    ),
    // transport_iroh.rs is the module that ACCEPTS peer connections and probes an
    // inert supply catalog. The scope note used to say the unscanned modules "do
    // not answer peer messages today", which was simply false of this one - and
    // the enumeration API its own docs anticipate (task-50) would have landed
    // exactly here, outside the guard.
    (
        // MOVED below the seam into fabric-iroh (TASK-148 inc 2); cited by relative
        // path so this no-enumeration guard still scans the module that accepts peer
        // connections.
        "transport_iroh.rs",
        include_str!("../../fabric-iroh/src/transport_iroh.rs"),
    ),
];

/// Identity types whose PLURAL return is a potential holdings listing.
const IDENTITY_TYPES: &[&str] = &[
    "NarHashKey",
    "Blake3Digest",
    "Claim",
    "StorePath",
    // Every `Have` carries a blake3, so a Vec of these IS a holdings listing -
    // built out of the project's own types, which is what made it easy to miss.
    "BatchHoldAnswer",
    // One PersistedRegistration is a single `key -> store_path` holding record
    // (task-82: plus its verified derived Blake3Digest); a Vec of them IS this
    // node's whole registration set - the very listing the invariant forbids
    // handing to a peer. task-82 changed `IndexStore::load`'s return from a bare
    // key list to `Vec<PersistedRegistration>`, and because this type was not
    // listed the guard stopped seeing `load` AT ALL - matching nothing where it
    // once caught the local-persistence read. It is exempted below (a startup
    // read of THIS node's own file, not wire-reachable), not invisible.
    "PersistedRegistration",
];

/// Types that CARRY a collection of holdings inside them, so returning one bare -
/// with no container in sight - is just as much a listing as returning a `Vec`.
/// This is the hole a cross-model review walked straight through.
const PLURAL_WRAPPERS: &[&str] = &["BatchHoldResponse"];

/// Parameter types that constitute "the caller named the keys". The identity types
/// themselves, plus the QUERY types - which exist precisely to carry a caller's
/// named keys and are how a wire-facing responder receives them.
const KEY_BEARING_PARAMS: &[&str] = &["NarHashKey", "Blake3Digest", "HoldQuery", "BatchHoldQuery"];

/// Per-FILE floor on how many signatures the parser must find. Deliberately low
/// enough that adding or removing a few functions does not churn it, and high
/// enough that a file which failed to parse at all cannot slip through. Seven is
/// the real minimum among the governed modules (`supply_catalog.rs`); inflating
/// it by adding a no-op API would weaken the production boundary to satisfy a
/// test implementation detail.
const MIN_SIGNATURES_PER_FILE: usize = 7;

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
/// SCOPED BY (FILE, IMPL BLOCK, NAME). File scoping alone was not enough: two
/// different types in ONE file can both have a `load`, so the argument written
/// for `IndexStore::load` was silently inherited by any other `load` added
/// beside it. The impl block is the unit an exemption actually reasons about.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    // The local-persistence seam: the trait DECLARATION and each implementation
    // are listed separately, because an exemption is an argument about one
    // function and the impls are different functions from the declaration.
    (
        "availability.rs",
        "IndexStore",
        "load",
        "IndexStore::load reads THIS node's own persisted registrations off local \
         disk at startup. It is not reachable from any wire message - no peer \
         input can cause it to be called - and a node is obviously allowed to \
         know its own index.",
    ),
    (
        "availability.rs",
        "NullStore",
        "load",
        "The no-op implementation of IndexStore::load; it returns an empty vector.",
    ),
    (
        "availability.rs",
        "JsonFileStore",
        "load",
        "The on-disk implementation of IndexStore::load; same local-startup \
         argument, reading this node's own file.",
    ),
    (
        "availability.rs",
        "IndexStore",
        "save",
        "IndexStore::save is the write direction of the same local persistence \
         seam; it takes the entries as an argument.",
    ),
    (
        "claim.rs",
        "",
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
    item: String,
    name: String,
    params: String,
    ret: String,
}

/// Extract every function signature from `src`. Deliberately simple: doc comments
/// and line comments are stripped first, then each `fn` is accumulated up to the
/// start of its body.
/// Is this line a function DECLARATION, whatever visibility and modifiers it
/// carries? Returns the byte offset of the `fn` keyword.
///
/// A CLASS check, not a list of prefixes. The previous version enumerated five
/// literal prefixes, so `pub(crate) async fn`, `pub(super) fn`, `pub const fn`
/// and `pub(in path) fn` were all invisible - and a guard that only sees the
/// forms someone remembered to list is not a guard. Every form is derived from
/// the grammar instead: an optional `pub` with an optional `(...)` restriction,
/// then any run of the modifier keywords, then `fn`.
fn declares_fn(line: &str) -> Option<usize> {
    let mut at = 0usize;
    let rest = line.trim_start();
    at += line.len() - rest.len();

    let mut rest = rest;
    if let Some(after_pub) = rest.strip_prefix("pub") {
        // `pub`, or `pub(crate)` / `pub(super)` / `pub(in some::path)`.
        let consumed_pub = 3;
        let mut consumed = consumed_pub;
        let trimmed = after_pub.trim_start();
        consumed += after_pub.len() - trimmed.len();
        if let Some(open_rest) = trimmed.strip_prefix('(') {
            let close = open_rest.find(')')?;
            consumed += 1 + close + 1;
        } else if !after_pub.starts_with(char::is_whitespace) && !after_pub.is_empty() {
            // `public_thing` is not `pub`; only a boundary counts.
            return None;
        }
        at += consumed;
        rest = &line[at..];
    }

    // Any order of these is accepted; rustc is stricter, but a guard that is
    // stricter than rustc would miss code that compiles.
    loop {
        let trimmed = rest.trim_start();
        at += rest.len() - trimmed.len();
        let mut advanced = false;
        for keyword in ["const", "async", "unsafe", "default", "extern"] {
            if trimmed
                .strip_prefix(keyword)
                .is_some_and(|after| after.starts_with(char::is_whitespace))
            {
                at += keyword.len();
                rest = &line[at..];
                advanced = true;
                break;
            }
        }
        // `extern "C"` carries an ABI string before `fn`.
        let trimmed = rest.trim_start();
        if let Some(end) = trimmed
            .strip_prefix('"')
            .and_then(|after_quote| after_quote.find('"'))
        {
            at += (rest.len() - trimmed.len()) + end + 2;
            rest = &line[at..];
            advanced = true;
        }
        if !advanced {
            break;
        }
    }

    let trimmed = rest.trim_start();
    at += rest.len() - trimmed.len();
    if trimmed == "fn" || trimmed.starts_with("fn ") || trimmed.starts_with("fn<") {
        Some(at)
    } else {
        None
    }
}

/// The subject of a block, if this line opens one: `impl<T> Trait for Type` and
/// `impl Type` yield `Type`, and `trait Name` yields `Name`.
///
/// Traits are tracked as well as impls because a trait DECLARATION is where an
/// enumeration method's contract is actually written - the impls only satisfy it.
/// Without this the declaration parsed with an empty owner and could not be
/// exempted or blamed by name.
fn impl_subject(line: &str) -> Option<String> {
    let line = line.trim_start();
    if let Some(rest) = line.strip_prefix("trait ") {
        return Some(
            rest.trim()
                .split(['<', ' ', '{', ':'])
                .next()
                .unwrap_or("")
                .to_string(),
        );
    }
    if let Some(rest) = line.strip_prefix("pub trait ") {
        return Some(
            rest.trim()
                .split(['<', ' ', '{', ':'])
                .next()
                .unwrap_or("")
                .to_string(),
        );
    }
    let rest = line.strip_prefix("impl")?;
    if !rest.starts_with(char::is_whitespace) && !rest.starts_with('<') {
        return None;
    }
    let body = rest.trim_start_matches(|c: char| c.is_whitespace());
    // Skip any generic parameter list directly after `impl`.
    let body = if body.starts_with('<') {
        let mut depth = 0usize;
        let mut end = 0usize;
        for (idx, ch) in body.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = idx + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        &body[end..]
    } else {
        body
    };
    let subject = match body.find(" for ") {
        Some(at) => &body[at + 5..],
        None => body,
    };
    Some(
        subject
            .trim()
            .trim_end_matches('{')
            .trim()
            .split(['<', ' '])
            .next()
            .unwrap_or("")
            .to_string(),
    )
}

/// Extract every function signature from `src`, with the `impl` block it sits in.
///
/// `#[cfg(test)]` items are skipped by BRACE MATCHING, one item at a time. The
/// previous version did `take_while(line != "#[cfg(test)]")`, which truncated the
/// whole file at the FIRST such attribute - and `claim.rs` has one near the top,
/// so everything after it went unparsed. A blatant
/// `pub fn harvest_every_key_i_know() -> Vec<NarHashKey>` placed below it passed
/// at exit 0, in the plainest recognised form, because the parser never saw it.
fn signatures(file: &'static str, src: &str) -> Vec<Signature> {
    let raw: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect();

    // Pass 1: drop `#[cfg(test)]` items, keeping everything around them.
    let mut code: Vec<&str> = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] != "#[cfg(test)]" {
            code.push(raw[i]);
            i += 1;
            continue;
        }
        i += 1;
        // Skip the annotated item: either a braced block or a one-line decl.
        let mut depth = 0usize;
        let mut opened = false;
        while i < raw.len() {
            depth += raw[i].matches('{').count();
            if raw[i].contains('{') {
                opened = true;
            }
            depth = depth.saturating_sub(raw[i].matches('}').count());
            i += 1;
            if opened && depth == 0 {
                break;
            }
            if !opened && raw[i - 1].ends_with(';') {
                break;
            }
        }
    }

    // Pass 2: signatures, tracking the enclosing `impl` subject by brace depth.
    let mut out = Vec::new();
    let mut impl_stack: Vec<(usize, String)> = Vec::new();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < code.len() {
        let line = code[i];
        while impl_stack.last().is_some_and(|(at, _)| depth <= *at) {
            impl_stack.pop();
        }
        if let Some(subject) = impl_subject(line) {
            impl_stack.push((depth, subject));
        }
        let item = impl_stack
            .last()
            .map(|(_, name)| name.clone())
            .unwrap_or_default();

        let Some(fn_at_in_line) = declares_fn(line) else {
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
            i += 1;
            continue;
        };
        let _ = fn_at_in_line;

        // Accumulate until the body opens or the (trait) declaration ends.
        let mut sig = String::new();
        while i < code.len() {
            sig.push_str(code[i]);
            sig.push(' ');
            let ends = code[i].ends_with('{') || code[i].ends_with(';');
            depth += code[i].matches('{').count();
            depth = depth.saturating_sub(code[i].matches('}').count());
            if ends {
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
        let mut paren = 0usize;
        let mut close = None;
        for (idx, ch) in sig.char_indices().skip(open) {
            match ch {
                '(' => paren += 1,
                ')' => {
                    paren -= 1;
                    if paren == 0 {
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
            item,
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
    let mut per_file: Vec<(&str, usize)> = Vec::new();
    let mut plural_returns: Vec<String> = Vec::new();

    for (file, src) in SOURCES {
        let mut checked = 0usize;
        for sig in signatures(file, src) {
            checked += 1;
            if !returns_plural_identity(&sig.ret) {
                continue;
            }
            plural_returns.push(sig.name.clone());
            if ALLOWED.iter().any(|(allowed_file, item, name, _)| {
                *allowed_file == *file && *item == sig.item && *name == sig.name
            }) {
                continue;
            }
            if !mentions(&sig.params, KEY_BEARING_PARAMS) {
                violations.push(format!(
                    "{}::{}::{} returns plural holdings ({}) without being handed any \
                     key - that is an enumeration API",
                    sig.file,
                    sig.item,
                    sig.name,
                    sig.ret.trim().trim_end_matches('{').trim()
                ));
            }
        }
        per_file.push((file, checked));
    }

    assert!(
        violations.is_empty(),
        "no-enumeration violations:\n  {}",
        violations.join("\n  ")
    );

    // The guard must actually be LOOKING at something - PER FILE. A single global
    // floor is not a floor: the parser once truncated `claim.rs` entirely at its
    // first `#[cfg(test)]` and still counted 57 functions from the other two
    // modules, sailing past a `> 60` global check while an entire module went
    // unscanned. Losing a whole file has to be detectable as such.
    for (file, checked) in &per_file {
        assert!(
            *checked >= MIN_SIGNATURES_PER_FILE,
            "the signature parser found only {checked} functions in {file} (floor \
             {MIN_SIGNATURES_PER_FILE}); it is not parsing that source - which is a \
             SILENT pass, because an unparsed file has no violations"
        );
    }
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
fn the_guard_bites_on_an_enumeration_of_the_persisted_registration_set() {
    // A regression bite for TASK-196. `IndexStore::load` returns
    // `Vec<PersistedRegistration>` (task-82 changed it from a bare key list); one
    // PersistedRegistration is a single holding record, so a Vec of them is this
    // node's whole registration set. When that type was absent from IDENTITY_TYPES
    // the rule stopped seeing `load` at all - it matched NOTHING. This proves the
    // added arm fails-closed: an un-exempted method dumping the set with no key in
    // is caught, and the honest per-key form is not.
    let hostile = r#"
        impl AvailabilityIndex {
            pub fn dump_all_registrations(&self) -> Vec<PersistedRegistration> {
            }
        }
    "#;
    let sigs = signatures("discovery.rs", hostile);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].name, "dump_all_registrations");
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "a Vec<PersistedRegistration> return must count as plural holdings"
    );
    assert!(
        !mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "it is handed no keys, so the rule must reject it"
    );
    // It is caught only because it is NOT in the exemption list - unlike the three
    // IndexStore::load impls, which are exempt as local-startup reads.
    assert!(
        !ALLOWED.iter().any(|(file, item, name, _)| {
            *file == sigs[0].file && *item == sigs[0].item && *name == sigs[0].name
        }),
        "discovery.rs::dump_all_registrations must NOT be exempt"
    );

    // The per-key form, handed the caller's keys, is legitimate and passes.
    let legitimate = r#"
        impl AvailabilityIndex {
            pub fn registrations_for(&self, keys: &[NarHashKey]) -> Vec<PersistedRegistration> {
            }
        }
    "#;
    let sigs = signatures("availability.rs", legitimate);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "a caller-supplied key list is what makes a plural answer legitimate"
    );
}

#[test]
fn an_exemption_does_not_leak_across_files_or_impl_blocks() {
    // `IndexStore::load` is exempt in availability.rs (local persistence). The
    // same name must NOT inherit that argument - not in another file, and not in
    // another impl block in the SAME file, which file scoping alone allowed.
    let exempt = ALLOWED.iter().any(|(file, item, name, _)| {
        *file == "availability.rs" && *item == "IndexStore" && *name == "load"
    });
    assert!(
        exempt,
        "the availability.rs::IndexStore::load exemption must exist"
    );
    let leaked_file = ALLOWED
        .iter()
        .any(|(file, _, name, _)| *file == "discovery.rs" && *name == "load");
    assert!(
        !leaked_file,
        "an exemption is an argument about ONE function in ONE file"
    );

    // THE SAME-FILE CASE, which is what (file, name) scoping could not express: a
    // DIFFERENT type in availability.rs with a `load` that lists holdings is a
    // violation, and must not be covered by IndexStore's argument.
    let sibling = r#"
        impl Harvester {
            pub fn load(&self) -> Vec<NarHashKey> {
            }
        }
    "#;
    let sigs = signatures("availability.rs", sibling);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].item, "Harvester", "the impl block must be recorded");
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        !ALLOWED.iter().any(|(file, item, name, _)| {
            *file == sigs[0].file && *item == sigs[0].item && *name == sigs[0].name
        }),
        "availability.rs::Harvester::load must NOT inherit IndexStore::load's exemption"
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
        !ALLOWED.iter().any(|(file, item, name, _)| {
            *file == "discovery.rs" && *item == sigs[0].item && *name == sigs[0].name
        }),
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
fn every_source_clears_the_per_file_floor_and_an_unparsed_one_does_not() {
    // The floor exists to make "a whole file silently went unparsed" detectable.
    // A GLOBAL floor could not: with `claim.rs` truncated entirely, the other
    // modules still supplied 57 signatures and sailed past a `> 60` global check.
    // Both directions are asserted, so the floor is a discriminator rather than a
    // number that happens to be true.
    for (file, src) in SOURCES {
        let found = signatures(file, src).len();
        assert!(
            found >= MIN_SIGNATURES_PER_FILE,
            "{file} parsed to only {found} signatures (floor {MIN_SIGNATURES_PER_FILE})"
        );
    }
    for unparseable in ["", "// only a comment", "struct S { a: u8 }"] {
        assert!(
            signatures("claim.rs", unparseable).len() < MIN_SIGNATURES_PER_FILE,
            "a source with no functions must fall BELOW the floor, or the floor \
             cannot detect a file that failed to parse"
        );
    }
}

#[test]
fn the_parser_is_not_truncated_by_a_cfg_test_item() {
    // THE WORST DEFECT THIS GUARD HAS HAD. The line filter was
    // `take_while(line != "#[cfg(test)]")`, which truncated the ENTIRE FILE at the
    // first such attribute. `claim.rs` has one well before the end, so a blatant
    // `pub fn harvest_every_key_i_know() -> Vec<NarHashKey>` placed after it was
    // never parsed and the suite passed at exit 0 - in the plainest recognised
    // form, defeated by position alone.
    let src = r#"
        #[cfg(test)]
        fn a_test_helper() -> Vec<NarHashKey> {
        }

        impl AvailabilityIndex {
            pub fn harvest_every_key_i_know(&self) -> Vec<NarHashKey> {
            }
        }
    "#;
    let sigs = signatures("availability.rs", src);
    assert!(
        sigs.iter().any(|s| s.name == "harvest_every_key_i_know"),
        "a function AFTER a #[cfg(test)] item must still be parsed; saw {:?}",
        sigs.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    assert!(
        !sigs.iter().any(|s| s.name == "a_test_helper"),
        "the #[cfg(test)] item itself must still be skipped"
    );
    // ...and a #[cfg(test)] MODULE, the common shape, is skipped whole.
    let with_mod = r#"
        #[cfg(test)]
        mod tests {
            fn helper() -> Vec<NarHashKey> {
            }
        }

        pub fn after_the_module(&self) -> Vec<NarHashKey> {
        }
    "#;
    let sigs = signatures("claim.rs", with_mod);
    let names: Vec<&String> = sigs.iter().map(|s| &s.name).collect();
    assert!(
        names.iter().any(|n| *n == "after_the_module") && !names.iter().any(|n| *n == "helper"),
        "a cfg(test) MODULE is skipped whole and parsing resumes after it; saw {names:?}"
    );
}

#[test]
fn every_function_form_is_seen_not_just_the_listed_prefixes() {
    // A CLASS check. The previous version enumerated five literal prefixes, so
    // four more forms were invisible - and all four were verified to smuggle a
    // real enumeration API into availability.rs at exit 0. Fixing them one at a
    // time is what let this recur: the third defect was fixed while four more of
    // the same species stayed in the same list.
    let forms = [
        ("fn plain() -> Vec<NarHashKey> {", "plain"),
        ("pub fn public() -> Vec<NarHashKey> {", "public"),
        (
            "async fn asynchronous() -> Vec<NarHashKey> {",
            "asynchronous",
        ),
        ("pub async fn pub_async() -> Vec<NarHashKey> {", "pub_async"),
        (
            "pub(crate) fn crate_vis() -> Vec<NarHashKey> {",
            "crate_vis",
        ),
        (
            "pub(crate) async fn crate_async() -> BatchHoldResponse {",
            "crate_async",
        ),
        (
            "pub(crate) async fn crate_claims() -> Vec<Claim> {",
            "crate_claims",
        ),
        (
            "pub(super) fn super_vis() -> Vec<NarHashKey> {",
            "super_vis",
        ),
        ("pub const fn const_vis() -> Vec<NarHashKey> {", "const_vis"),
        (
            "pub(in crate::daemon) fn path_vis() -> Vec<NarHashKey> {",
            "path_vis",
        ),
        (
            "pub unsafe fn unsafe_vis() -> Vec<NarHashKey> {",
            "unsafe_vis",
        ),
    ];
    for (line, expected) in forms {
        let sigs = signatures("availability.rs", line);
        assert_eq!(
            sigs.len(),
            1,
            "`{line}` was not recognised as a function declaration at all"
        );
        assert_eq!(
            sigs[0].name, expected,
            "parsed the wrong name from `{line}`"
        );
        assert!(
            returns_plural_identity(&sigs[0].ret),
            "`{line}` returns plural holdings but the guard did not see it"
        );
        assert!(
            !mentions(&sigs[0].params, KEY_BEARING_PARAMS),
            "`{line}` takes no keys, so it must count as an enumeration API"
        );
    }
    // The CONTROL: things that merely look like declarations are NOT functions.
    for benign in [
        "let f = |x| x + 1;",
        "where F: Fn(&str) -> Vec<NarHashKey>,",
        "pub struct Confusing { field: Vec<NarHashKey> }",
        "public_helper_not_pub();",
    ] {
        assert!(
            signatures("availability.rs", benign).is_empty(),
            "`{benign}` is not a function declaration"
        );
    }
}

#[test]
fn a_vec_of_batch_answers_is_a_holdings_listing() {
    // Every `Have` carries a blake3, so a Vec of answers IS a listing - built out
    // of the project's own types, which is exactly why it read as innocuous.
    let hostile = r#"
        impl AvailabilityIndex {
            pub fn everything(&self) -> Vec<BatchHoldAnswer> {
            }
        }
    "#;
    let sigs = signatures("availability.rs", hostile);
    assert_eq!(sigs.len(), 1);
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "Vec<BatchHoldAnswer> must count as plural holdings"
    );
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
