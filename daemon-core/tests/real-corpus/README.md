# Real cache.nixos.org narinfo corpus (TASK-254)

Vendored, UNMODIFIED narinfos fetched from `https://cache.nixos.org` (owner signed
off on real-cache contact) with an identifying user-agent over a handful of polite
sequential GETs. They exist so the SHIPPED narinfo parse + rewrite path
(`daemon_core::catalog::parse_correlation` + `daemon_core::to_raw`) is
conformance-tested against the cache's ACTUAL behaviour - COMPRESSED archives -
rather than only the mock suite's near-universal `Compression: none` fixtures.

Exercised by `daemon-core/tests/real_corpus_narinfo.rs` (runs under `just test` via
the default workspace test set; embedded with `include_str!`, so the bytes are
frozen at compile time and the test bites on any corpus change).

Shapes captured (deliberately spanning both codings and a References-absent case):

| file                | Compression | NarSize (raw) | FileSize (compressed) | References |
|---------------------|-------------|---------------|-----------------------|------------|
| hello.narinfo       | xz          | 274568        | 57568                 | present    |
| bash.narinfo        | xz          | 1654112       | 448312                | present    |
| git.narinfo         | xz          | 50548816      | 8011464               | present    |
| glibc.narinfo       | xz          | 3070464       | 234832                | present    |
| coreutils.narinfo   | zstd        | 1059840       | 262221                | ABSENT     |
| curl.narinfo        | zstd        | 1181408       | 554177                | present    |
| python3.narinfo     | zstd        | 133215664     | 56616908              | present    |

`NarSize` (uncompressed NAR) and `FileSize` (compressed transport) are DIFFERENT
UNITS and genuinely differ on every entry - the exact shape the mock fixtures
(where the two coincide) never exercised. `coreutils` carries NO `References:`
line, a real shape the mock never produces.
