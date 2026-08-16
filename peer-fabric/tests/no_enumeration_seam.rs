//! TASK-100 AC#4 - the no-enumeration invariant as a STRUCTURAL guard over the SEAM
//! discovery surface (`capabilities.rs`, `resolve.rs`).
//!
//! The PRD privacy invariant is "a peer cannot be asked what it holds". The batch
//! resolution contract (TASK-100) is the first SEAM message whose SHAPE resembles a
//! listing - a vector of per-key answers. It is not one: it is POSITIONAL over keys
//! the asker supplied ([`BatchResolveRequest`]) and carries no key of its own. But
//! "it is not one because of how we populate it" is a property a later change could
//! quietly remove; this guard makes it a rule about the API's TYPES:
//!
//!   if a function's RETURN type contains a multi-valued container of a HOLDING
//!   identity (`ProviderRecord`, `KeyResolution`, `HoldAnswer`), OR is one of the
//!   WRAPPER types that carries such a collection (`BatchResolution`, `PeerHoldReply`),
//!   then its PARAMETERS must name a key-bearing input (`ContentKey`,
//!   `BatchResolveRequest`, `PeerHoldRequest`).
//!
//! Plural holdings out require named keys in. A `fn list_all(&self) -> Vec<ProviderRecord>`
//! fails; `fn resolve_batch(&self, r: &BatchResolveRequest) -> BatchResolution` passes,
//! because a `BatchResolveRequest` IS the caller's named keys. The self-tests at the
//! bottom prove the guard BITES (a keyless plural is caught) and is not vacuous (the
//! keyed form passes) - AC#4's negative mutation.
//!
//! The signature parser is copied VERBATIM from the daemon-core no-enumeration guard
//! (`daemon/tests/no_enumeration.rs`), which a cross-model review hardened against many
//! adversarial shapes (`pub(crate) fn`, `#[cfg(test)]` truncation, wrapper-type returns,
//! per-impl-block exemptions). Two guards exist because they cover two crates with two
//! type vocabularies; the parser is the shared, proven core.

// The two files that make up the SEAM discovery surface.
const SOURCES: &[(&str, &str)] = &[
    ("capabilities.rs", include_str!("../src/capabilities.rs")),
    ("resolve.rs", include_str!("../src/resolve.rs")),
];

/// HOLDING identity types whose PLURAL return is a potential inventory listing.
const IDENTITY_TYPES: &[&str] = &["ProviderRecord", "KeyResolution", "HoldAnswer"];

/// Types that CARRY a collection of holdings inside them, so returning one bare is
/// just as much a listing as returning a `Vec`.
const PLURAL_WRAPPERS: &[&str] = &["BatchResolution", "PeerHoldReply"];

/// Parameter types that constitute "the caller named the keys": a key itself, or the
/// positional query wrappers that exist precisely to carry a caller's named keys.
const KEY_BEARING_PARAMS: &[&str] = &["ContentKey", "BatchResolveRequest", "PeerHoldRequest"];

/// Container shapes that make a return value plural.
const CONTAINERS: &[&str] = &[
    "Vec<",
    "HashMap<",
    "HashSet<",
    "BTreeMap<",
    "&[",
    "Iterator<",
];

const MIN_SIGNATURES_PER_FILE: usize = 7;

/// Functions exempted from the rule, scoped by (FILE, IMPL BLOCK, NAME), each with the
/// reason it is not a peer-facing listing. These are ACCESSORS on a value that was
/// ALREADY built from a keyed request - they read holdings the asker's own keys
/// produced, not an inventory the asker did not name.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "resolve.rs",
        "KeyResolution",
        "holders",
        "KeyResolution::holders reads the holders of a SINGLE per-key outcome that was \
         produced BY a keyed BatchResolveRequest; it is an accessor on an answer, not a \
         query. The keys came from the asker's request; this returns the holders one of \
         them resolved to.",
    ),
    (
        "resolve.rs",
        "BatchResolution",
        "outcomes",
        "BatchResolution::outcomes is the POSITIONAL accessor over the asker's own \
         request keys (aligned_with is the checked reader). It carries no keys of its \
         own and is meaningless without the request that produced it.",
    ),
];

#[derive(Debug)]
struct Signature {
    file: &'static str,
    item: String,
    name: String,
    params: String,
    ret: String,
}

fn declares_fn(line: &str) -> Option<usize> {
    let mut at = 0usize;
    let rest = line.trim_start();
    at += line.len() - rest.len();

    let mut rest = rest;
    if let Some(after_pub) = rest.strip_prefix("pub") {
        let consumed_pub = 3;
        let mut consumed = consumed_pub;
        let trimmed = after_pub.trim_start();
        consumed += after_pub.len() - trimmed.len();
        if let Some(open_rest) = trimmed.strip_prefix('(') {
            let close = open_rest.find(')')?;
            consumed += 1 + close + 1;
        } else if !after_pub.starts_with(char::is_whitespace) && !after_pub.is_empty() {
            return None;
        }
        at += consumed;
        rest = &line[at..];
    }

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

fn impl_subject(line: &str) -> Option<String> {
    let line = line.trim_start();
    let vis_stripped = {
        let mut s = line;
        if let Some(rest) = s.strip_prefix("pub") {
            let rest = rest.trim_start();
            let rest = if let Some(after) = rest.strip_prefix('(') {
                match after.find(')') {
                    Some(close) => after[close + 1..].trim_start(),
                    None => rest,
                }
            } else {
                rest
            };
            s = rest;
        }
        s
    };
    if let Some(rest) = vis_stripped.strip_prefix("trait ") {
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

fn signatures(file: &'static str, src: &str) -> Vec<Signature> {
    let raw: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect();

    let mut code: Vec<&str> = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] != "#[cfg(test)]" {
            code.push(raw[i]);
            i += 1;
            continue;
        }
        i += 1;
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

        let Some(_fn_at) = declares_fn(line) else {
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
            i += 1;
            continue;
        };

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

fn returns_plural_identity(ret: &str) -> bool {
    returns_plural_container(ret) || mentions(ret, PLURAL_WRAPPERS)
}

#[test]
fn no_seam_function_returns_plural_holdings_it_was_not_given() {
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
        "seam no-enumeration violations:\n  {}",
        violations.join("\n  ")
    );
    for (file, checked) in &per_file {
        assert!(
            *checked >= MIN_SIGNATURES_PER_FILE,
            "the signature parser found only {checked} functions in {file} (floor \
             {MIN_SIGNATURES_PER_FILE}); it is not parsing that source"
        );
    }
    // It must SEE the batch methods that really do return plural holdings, by name.
    for expected in ["find_providers", "resolve_batch", "resolve", "outcomes"] {
        assert!(
            plural_returns.iter().any(|name| name == expected),
            "the rule did not even notice `{expected}`, which returns plural holdings; \
             it is matching nothing. Saw: {plural_returns:?}"
        );
    }
}

#[test]
fn the_seam_guard_bites_on_a_synthetic_inventory_api() {
    // AC#4 negative mutation: an inventory method that dumps holdings with NO key in
    // must be caught, or the guard proves nothing.
    let hostile = r#"
        impl Libp2pProviderDirectory {
            pub fn list_all(&self) -> Vec<ProviderRecord> {
                self.everything()
            }
        }
    "#;
    let sigs = signatures("resolve.rs", hostile);
    assert_eq!(sigs.len(), 1, "the parser must find the hostile method");
    assert_eq!(sigs[0].name, "list_all");
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "a Vec<ProviderRecord> return must be recognised as plural holdings"
    );
    assert!(
        !mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "and it takes no key - so the rule must reject it"
    );
    assert!(
        !ALLOWED
            .iter()
            .any(|(_, item, name, _)| { *item == sigs[0].item && *name == sigs[0].name }),
        "list_all must NOT be exempt"
    );

    // A bare BatchResolution return with no key is likewise an inventory dump.
    let wrapper = r#"
        impl Libp2pProviderDirectory {
            pub fn everything(&self) -> BatchResolution {
                todo!()
            }
        }
    "#;
    let sigs = signatures("resolve.rs", wrapper);
    assert!(
        returns_plural_identity(&sigs[0].ret),
        "a bare BatchResolution return must count as plural holdings"
    );
    assert!(!mentions(&sigs[0].params, KEY_BEARING_PARAMS));
}

#[test]
fn the_seam_guard_passes_the_keyed_batch_form() {
    // Not vacuous: the honest batch method, handed the asker's own keys, passes.
    let legitimate = r#"
        impl Libp2pProviderDirectory {
            pub fn resolve_batch(&self, request: &BatchResolveRequest) -> BatchResolution {
            }
        }
    "#;
    let sigs = signatures("resolve.rs", legitimate);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(
        mentions(&sigs[0].params, KEY_BEARING_PARAMS),
        "a BatchResolveRequest IS the caller's named keys"
    );

    // And the single-key form keyed by a ContentKey passes too.
    let single = r#"
        impl Libp2pProviderDirectory {
            pub fn find_providers(&self, key: &ContentKey) -> Lookup<Vec<ProviderRecord>> {
            }
        }
    "#;
    let sigs = signatures("resolve.rs", single);
    assert!(returns_plural_identity(&sigs[0].ret));
    assert!(mentions(&sigs[0].params, KEY_BEARING_PARAMS));
}
