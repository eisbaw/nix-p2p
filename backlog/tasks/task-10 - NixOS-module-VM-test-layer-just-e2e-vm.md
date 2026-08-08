---
id: TASK-10
title: NixOS module + VM test layer (just e2e-vm)
status: Done
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 17:18'
labels: []
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Minimal NixOS module (enable, port, upstream URL, nix.settings wiring for substituters + trusted key) and a NixOS VM test running the core scenario on real nix-daemon + systemd: the truth layer for S2 store-open behavior and service ordering. Reuses scenario definitions from the compose harness where practical - but do not force sharing that distorts either layer.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 VM test green: client VM substitutes fixture closure through daemon + testproxy/mock VMs; S1+S2 asserted; fixtures reach the upstream VM via virtualisation.additionalPaths and are asserted ABSENT from the client VM store (else S1 passes vacuously); client substituters forced via lib.mkForce
- [x] #2 Module: enable/port/upstream options, sets nix.settings substituter ordering with an explicit ?priority=10 URL param on the daemon substituter; daemon-off VM boots and builds via fallback (module-level additive invariant)
- [x] #3 just e2e-vm builds/runs the VM test via a dedicated flake output (e.g. packages or apps), NOT via checks consumed by nix flake check; only fast checks feed nix flake check and the devshell (codex task-1 finding 4: everything under checks gets built by nix flake check, and flake.nix feeds checks into the devshell - VM test there would make every gate slow)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Module should pin the daemon substituter with an explicit ?priority=10 URL param (client-side override, deterministic regardless of advertised priority) in addition to serving nix-cache-info Priority < 40. Ref: bmcgee.ie TIL post.

forward-carried from task-1 (e9b3378): the NixOS module must consume flake packages.x86_64-linux.daemon (crane-built; bin/daemon; meta.mainProgram = "daemon"), not a rebuilt derivation. That attribute name is a de-facto interface shared with task-5's container images - renaming it breaks both. The flake pins nixpkgs nixos-26.05 (crane requires >= 26.05) while the dev host is NixOS 25.11; VM tests run against the flake's nixpkgs, so that is the version your test nodes get. System is hardcoded to x86_64-linux. When this lands, DELETE the 'just e2e-vm' stub (currently exits 0 printing '0 scenarios registered - NOT a pass') and add a DoD grep for that marker requiring zero hits.

forward-carried from task-1 (acb37f3): 'nix flake check' now runs 7 real checks (daemon, testproxy, clippy, fmt, test, scripts, independence). If you add the VM test as a dedicated flake output rather than a check, say so explicitly in the task notes so nobody assumes 'nix flake check' covers it. packages.x86_64-linux.daemon is unchanged as the module's input and now has its own dependency closure.

forward-carried from task-3 (119cbb7): the VM test is one of the two places that can prove signature enforcement through the REAL nix-daemon path. scripts/check-fixtures.py proves it only in nix's direct store mode, where trusted-public-keys is a client-side option; a nix-daemon ignores that setting for a non-trusted user and enforces require-sigs itself from /etc/nix/nix.conf. So configure trusted-public-keys = <fixtures/out/test-key.pub> and require-sigs = true in the VM's nix.conf (never the module's defaults, which trust cache.nixos.org-1), and re-assert the three tampered narinfos there. Expected nix errors: 'lacks a signature by a trusted key' for a corrupted Sig and for a valid-but-untrusted-key signature, 'hash mismatch importing path' for a NarHash mutated and re-signed with the trusted key.

forward-carried from task-3 round 5: the fixture tree is now published as an immutable generation behind a symlink, so every path above that starts fixtures/out/ gains one level: fixtures/out/current/cache, fixtures/out/current/manifest.json, fixtures/out/current/test-key.pub. Resolve through fixtures/out/current (never name a generation directly); it is a relative symlink to generations/gen-<manifest-sha>, and the generation it points at is immutable, so a consumer that resolves it once cannot have the tree change underneath it. Retention is two generations, not a lease: re-resolve on ENOENT if you hold it across repeated regenerations.

--- from task-5 (80319ec): what the VM layer should reuse vs redo ---
REUSE: the scenario intent + oracle definitions (byte S1, paired request counts, S2 fallback, AC#3 three tampers, 404-fidelity) and the fixturelib tamper-tree builders (build_tamper_tree in e2e_harness.py). The nix.conf topology (daemon Priority<40 + explicit direct fallback, require-sigs on, trusted-public-keys = EXACTLY the test key). REDO for the VM: task-5 runs S1/S2/404 in single-user root nix and ONLY the AC#3 tampers through a hand-started nix-daemon+setpriv. The VM has a REAL systemd nix-daemon and the NixOS module, so it is the truth layer for S2 store-open behavior and service ordering - run ALL scenarios through the system nix-daemon there, with an untrusted user, and assert the SAME daemon-side message strings task-5 discovered: sig reject = "not signed by any of the keys in 'trusted-public-keys'", content = "hash mismatch importing path". Do NOT reuse the container port-publishing trick (VM has real networking). check-fixtures.py --require-tier full before serving stands.

DONE (task-10, wave-1 scope). NixOS module nixos/nix-p2p.nix + VM test nixos/vm-test.nix; e2e-vm green.

WIRING: just e2e-vm = `nix build -L --no-link .#vm-test` (dedicated PACKAGE output packages.x86_64-linux.vm-test), NOT a check. Proof fast gates stayed fast: nix eval .#checks lists 9 attrs (daemon testproxy clippy fmt test scripts source-guard lock-sources independence), NO vm-test; `nix flake check` ran 49.78s and only EVALUATED vm-test as a package ('derivation evaluated to ...vm-test-run...drv') - never built/booted QEMU. Module also exposed as flake nixosModules.nix-p2p / .default. Deleted the e2e-vm stub AND the now-dead stub_marker var (DoD grep '0 scenarios registered' = 0 hits).

VM PROOF (test script finished 17.77s, 3 nodes peer/client/daemonoff, one signed nix-serve cache):
- S1 byte-identity THROUGH the daemon: absent-before = 'path ... is not valid' (nix-validity, non-vacuous); realise app closure -> daemon journal logged TWO real substitutions 'daemon: substituted path=/nar/0a0lslqb... source=http://peer:5000 bytes=66048' (lib) + 'l30jg5xg... bytes=408' (app); present-after nix-store -q --hash == peer ground truth.
- S2 fallback: stop nix-p2p-daemon (curl 8082 fails), realise FRESH zstd -> nix logged 'Could not connect to 127.0.0.1:8082' on daemon(?priority=10) yet realise SUCCEEDED via peer(?priority=50); byte oracle matched; daemon still inactive. Fallback-served evidence = daemon provably down + invalid-before + valid-after-with-correct-hash.
- AC#3 module additive invariant: daemonoff node (module enable=true, systemd wantedBy mkForce []) never starts the daemon, boots, and realises via the module's OWN additive substituters (not mkForce) -> fallback; byte oracle matched.

DAEMON-SIDE TRUST (the VM's added value over task-5): client system /etc/nix/nix.conf via nix.settings.trusted-public-keys = lib.mkForce [<generated test key>], require-sigs = NixOS default true. A real systemd nix-daemon enforced it (setpriv trick NOT needed).

GOTCHAS / carried lessons:
1. ORACLE FIX (cost 2 slow VM runs): the nixos-test driver shares the host /nix/store over 9p, so fixture files are PHYSICALLY present on every node; 'test -e <fixturepath>' passes before any substitution and useNixStoreImage did NOT remove them. Correct oracle for 'absent from the store' = nix-VALIDITY: `nix-store -q --hash` fails ('not valid') for an unregistered path regardless of 9p presence. Combined with the daemon 'substituted' log line this is a STRONGER non-vacuousness proof than physical absence. Future VM scenarios: never use test -e for absent-before.
2. Signing key generated at BUILD TIME via nix-store --generate-binary-cache-key in a runCommand (needs HOME/NIX_STATE_DIR/NIX_CONF_DIR redirected to $TMPDIR or it dies creating /nix/var/nix/profiles). Public key read via IFD (builtins.readFile), so EVALUATING the vm-test package (e.g. under nix flake check / nix eval .#packages) builds that tiny key derivation (<1s, NOT QEMU). Non-fixed-output => key is random per cold build; fine for a one-shot slow gate. Minor cleanup candidate: runtime key-gen to drop the IFD.
3. narinfo disk cache left OFF (module narinfoCacheDir default null) - task-29 wires a default + StateDirectory (DynamicUser can't write an arbitrary abs path).

DEFERRED to hardening (task-13/14): three tamper narinfos + testproxy fault modes re-asserted through the systemd daemon (message strings 'not signed by any of the keys in trusted-public-keys' / 'hash mismatch importing path'), and VM-level request-count oracles. No product/module bug found (both earlier red runs were my test-oracle mistake).
<!-- SECTION:NOTES:END -->
