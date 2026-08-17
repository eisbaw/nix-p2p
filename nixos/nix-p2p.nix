# NixOS module for the nix-p2p decentralized binary-cache daemon (task-10).
#
# Two responsibilities, kept deliberately small:
#   1. Run the product daemon as a systemd service (real nix-daemon + systemd
#      is the S2 truth layer the container harness cannot reach).
#   2. Wire nix.settings ADDITIVELY so the local daemon is the PREFERRED
#      substituter while an explicit upstream stays as a direct fallback.
#
# The additive wiring is the module-level invariant AC#3 asserts: a node whose
# daemon never starts must still boot and substitute via the fallback. That is
# why the daemon carries an explicit `?priority=10` URL param and the upstream
# `?priority=50` - client-side ordering that is deterministic regardless of the
# priority a cache advertises in its nix-cache-info (ref: bmcgee.ie TIL).
#
# It consumes the flake's `packages.<system>.daemon` (crane single binary,
# meta.mainProgram = "daemon"); it never rebuilds the daemon. `package` is a
# required option so the module has no opinion on which build it runs.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.nix-p2p;
  # libp2p sub-options (TASK-207). Read here so the ExecStart assembly below stays
  # terse; every field is inert unless `cfg.libp2p.enable`.
  lcfg = cfg.libp2p;

  # TASK-120: the operator PROFILE is the authoritative, validated participation MODE. It maps
  # DOWN onto the shipped libp2p flags (the daemon binary owns the identical fail-fast checks, so
  # this stays a thin mapping surface, not a second policy). The four modes mirror
  # `daemon_core::SharingProfile`:
  #   * upstream-only  -> NO p2p give/consume flags (the fail-safe default; a fresh install)
  #   * consume-only   -> --libp2p-leech (fetch from peers, serve/announce NOTHING)
  #   * lan-share      -> --libp2p-provider over an isolated substrate (no public allowlist)
  #   * public-share   -> --libp2p-provider + --libp2p-announce-after-fetch + the public-NAR
  #                       allowlist door (per-NAR announce gate)
  # The profile is used only when libp2p is enabled; upstream-only needs no libp2p at all.
  profile = lcfg.profile;
  isProvider = lcfg.provider || profile == "lan-share" || profile == "public-share";
  isLeech = lcfg.leech || profile == "consume-only";
  # TASK-241: a ROUTER is a kad-server + relay that carries NO content (serves + announces
  # NOTHING). It is the DHT-infrastructure role the give/consume modes cannot express - a
  # dedicated bootstrap/relay root. Selected via `profile = "router"` (or the low-level `router`).
  isRouter = lcfg.router || profile == "router";
  wantsAnnounceAfterFetch = lcfg.announceAfterFetch || profile == "public-share";
  # Local daemon URL, pinned ahead of everything with an explicit priority so
  # ordering does not depend on the advertised nix-cache-info Priority.
  daemonSubstituter = "http://127.0.0.1:${toString cfg.port}?priority=10";
  # The upstream doubles as the direct fallback: when the daemon is down, Nix
  # skips it (connection refused) and substitutes here instead. Without this an
  # additive-invariant boot would have nowhere to fall back to.
  fallbackSubstituter = "${cfg.upstream}?priority=50";
in
{
  options.services.nix-p2p = {
    enable = lib.mkEnableOption "the nix-p2p decentralized binary cache daemon";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The daemon package to run. Wire the flake's
        `packages.<system>.daemon` here - the module never rebuilds it.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8082;
      description = ''
        TCP port the daemon listens on. Bound to 127.0.0.1 only: the daemon is
        a local substituter, not a network service.
      '';
    };

    upstream = lib.mkOption {
      type = lib.types.str;
      example = "http://cache.example.org:5000";
      description = ''
        Upstream binary cache the daemon fetches from. It is ALSO wired as an
        explicit direct-fallback substituter (`?priority=50`), so a daemon-off
        boot still substitutes.
      '';
    };

    trustedPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "cache.example.org-1:abc..." ];
      description = ''
        Public keys added to nix.settings.trusted-public-keys so the signed
        content the daemon relays is accepted. require-sigs stays on (the NixOS
        default); this module never turns signature checking off. Additive: it
        merges with the system default keys.
      '';
    };

    narinfoCacheDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/var/lib/nix-p2p/narinfo";
      description = ''
        Persistent narinfo disk-cache directory (daemon task-8). ON BY DEFAULT
        (TASK-29): a fresh service persists narinfo across restarts, so a warm
        daemon serves the repeat narinfo locally instead of re-fetching upstream
        (TASK-28 moved the fsync off the async worker, making default-enabling
        safe). The default lives ONE LEVEL BELOW the `StateDirectory`-managed
        `/var/lib/nix-p2p` (which the DynamicUser owns and can write); the daemon
        creates the `narinfo/` subdir. Set to `null` to turn the cache OFF (the
        module then passes `--no-narinfo-cache`). CAUTION: a CUSTOM path (anything
        other than the default) is treated as EXPLICIT, so if the DynamicUser cannot
        write it the daemon fails fast and systemd restart-loops - point it at a
        StateDirectory / `ReadWritePaths` the service owns. Privacy note: which narinfos were
        fetched are now recorded on LOCAL disk - a local, re-derivable, count-capped
        cache, not a network disclosure; TASK-120 will refine the state-dir/mode.
      '';
    };

    # ---- libp2p P2P node options (TASK-207) --------------------------------
    # ADDITIVE: with `libp2p.enable = false` (the default) the service is exactly
    # the wave-1 HTTP substituter above - no `--libp2p-*` flag is appended, so the
    # existing TASK-10 e2e-vm is untouched. Set `libp2p.enable` (with a package
    # that speaks the flags, i.e. `daemon-libp2p`) to deploy the shipped libp2p
    # node - the decentralized directory + NAR transfer + NAT traversal
    # (AutoNAT/DCUtR/relay). Each option maps 1:1 to a `daemon-libp2p` CLI flag;
    # daemon-libp2p owns the cross-flag validation (a provider needs a listen and a
    # seed/store; a consumer needs a bootstrap), so this module stays a thin
    # flag-assembly surface and does not re-encode that policy.
    libp2p = {
      enable = lib.mkEnableOption "the libp2p P2P node (decentralized directory + NAR transfer + NAT traversal)";

      profile = lib.mkOption {
        type = lib.types.enum [ "upstream-only" "consume-only" "lan-share" "public-share" "router" ];
        default = "upstream-only";
        description = ''
          The authoritative, validated operator PARTICIPATION MODE (TASK-120,
          `daemon_core::SharingProfile`). Maps onto the shipped libp2p flags:

          - `upstream-only` (DEFAULT, fail-safe): HTTP upstream fallback only. No P2P
            serving, publication, public-DHT participation or third-party discovery -
            merely enabling the service emits no P2P give/consume traffic.
          - `consume-only`: fetch from peers but serve NOTHING and announce NOTHING
            (appends `--libp2p-leech`). A consumer still discloses what it looks up.
          - `lan-share`: serve + announce over an isolated/LAN substrate (sets
            `--libp2p-provider`, no public allowlist).
          - `public-share`: serve + announce over a public substrate, gated per NAR by
            the public-NAR allowlist (sets `--libp2p-provider`,
            `--libp2p-announce-after-fetch`, and REQUIRES `publicAllowlistPath` +
            `libp2pTrustedPublicKeys`). Invalid/privacy-contradictory combinations FAIL
            at evaluation (see the assertions below) rather than silently downgrading.
          - `router` (TASK-241): a pure kad-SERVER + circuit-v2 relay for OTHERS, carrying
            NO content (sets `--libp2p-router`; serves NOTHING, announces NOTHING). This is
            the dedicated bootstrap/relay-root role the give/consume modes cannot express:
            `consume-only` is a kad CLIENT (cannot be a bootstrap root) and the provider
            modes require content to serve. Requires `listen`; `relayServer = false` makes
            it a kad-only bootstrap (no reservation service). Combining it with any give-side
            option FAILS at evaluation.

          The lower-level `provider`/`leech`/`announceAfterFetch` booleans still exist for
          fine control; the profile is the recommended surface and its guarantees are the
          ones the assertions enforce.
        '';
      };

      provider = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Run as a PROVIDER (`--libp2p-provider`): serve + announce the configured seeds/store paths. Usually set via `profile` instead.";
      };

      leech = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Consume-only LEECH (`--libp2p-leech`): fetch from peers, serve + announce NOTHING. Usually set via `profile = \"consume-only\"`.";
      };

      router = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "ROUTER (`--libp2p-router`, TASK-241): a kad-SERVER + relay for others, carrying NO content (serves + announces NOTHING). Requires `listen`. Usually set via `profile = \"router\"`.";
      };

      announceAfterFetch = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Announce-after-fetch (`--libp2p-announce-after-fetch`): become a discoverable holder of what you fetch, within an integer budget. Requires `provider`. Usually set via `profile = \"public-share\"`.";
      };

      relayServer = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Run the circuit-v2 relay SERVER (accept reservations + forward circuits).
          Default `true` (the permissionless-swarm intent: any public node helps
          NAT'd peers). Set `false` (appends `--libp2p-no-relay-server`) for a
          kad-only node - a dedicated bootstrap that offers NO reservation service,
          so it can never be an ALTERNATIVE relay path. relay-client/autonat/dcutr
          stay intact; only the server behaviour is dropped.
        '';
      };

      listen = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "/ip4/192.168.2.3/tcp/4001" "/ip4/10.0.0.5/tcp/4001/p2p/12D3.../p2p-circuit" ];
        description = ''
          `--libp2p-listen` multiaddrs (repeatable). A NAT'd provider lists TWO: a
          direct transport bind AND a relay `/…/p2p-circuit` reservation address.
        '';
      };

      externalAddresses = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "/ip4/10.0.0.5/tcp/4001" ];
        description = ''
          `--libp2p-external-address` self-advertised reachable multiaddrs
          (repeatable). A RELAY node sets its public address here so its circuit-v2
          reservation vouchers cite it (else clients abort NoAddressesInReservation).
        '';
      };

      bootstrap = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "12D3KooWBr7c...@/ip4/10.0.0.5/tcp/4001" ];
        description = "`--libp2p-bootstrap <PeerId>@<multiaddr>` kad entry peers (repeatable).";
      };

      scope = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "`--libp2p-scope`: the kad/identify network scope, isolating this network from others.";
      };

      identitySeed = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          `--libp2p-identity-seed` (64 hex chars = 32 bytes). Pins the node's PeerId so
          peers can address it offline (a relay/bootstrap node needs a fixed identity).
        '';
      };

      stateDir = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "`--libp2p-state-dir`: per-node durable identity + anti-rollback state directory.";
      };

      provideStore = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "sha256:0pgs...=/nix/store/xxxx-foo" ];
        description = "`--libp2p-provide-store <narhash>=<storepath>`: serve a real store path via `nix-store --dump` on demand (repeatable).";
      };

      seedNar = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "`--libp2p-seed-nar <narhash>=<path/to/raw.nar>`: serve an in-memory raw NAR (repeatable).";
      };

      printPeerAddress = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "`--libp2p-print-peer-address`: log the provider's PeerId + listen addresses (LIBP2P-PROVIDER-ADDR).";
      };

      publicAllowlistPath = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          `--libp2p-public-allowlist-path`: the on-disk public-NAR allowlist that
          gates a PROVIDER's public (bootstrapped) announce. NOTE: with the default
          DynamicUser sandbox, `StateDirectory=nix-p2p` makes /var/lib/nix-p2p a
          SYMLINK, and the daemon's O_NOFOLLOW parent-dir check refuses a symlinked
          parent - so point this at a path ONE LEVEL BELOW the state root, e.g.
          `/var/lib/nix-p2p/state/allowlist` (the daemon creates the `state/` dir).
        '';
      };

      libp2pTrustedPublicKeys = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "`--libp2p-trusted-public-key`: trusted narinfo-signing keys that prove a NAR public for the announce allowlist (repeatable).";
      };

      provePublicNarinfo = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "l30jg5xg...=/path/to/foo.narinfo" ];
        description = "`--libp2p-prove-public-narinfo <store-hash>=<narinfo>`: prove each seed public at startup, populating the allowlist (repeatable).";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # TASK-120 AC#2: invalid or privacy-contradictory profile combinations FAIL at EVALUATION,
    # precisely - never a silent downgrade into a weaker-than-asked mode. These mirror the daemon
    # binary's fail-fast checks (`daemon_core::SharingProfile::derive`), catching the misconfig at
    # `nixos-rebuild` time instead of a systemd restart-loop.
    assertions = [
      {
        # A consume-only leech gives nothing back: it cannot also be a provider / announce / allowlist.
        assertion = !(isLeech && (isProvider || wantsAnnounceAfterFetch || lcfg.publicAllowlistPath != null));
        message = "services.nix-p2p.libp2p: consume-only/leech serves NOTHING and announces NOTHING; it cannot be combined with a provider profile, announceAfterFetch, or a public allowlist. Choose one participation mode.";
      }
      {
        # public-share REQUIRES the per-NAR allowlist door - otherwise it is not the gated public mode.
        assertion = profile != "public-share" || lcfg.publicAllowlistPath != null;
        message = "services.nix-p2p.libp2p.profile = \"public-share\" requires libp2p.publicAllowlistPath (the per-NAR announce gate). Set it, or use \"lan-share\" for an isolated substrate.";
      }
      {
        # A public allowlist with no trusted key can prove NOTHING public - every announce would refuse.
        assertion = lcfg.publicAllowlistPath == null || lcfg.libp2pTrustedPublicKeys != [ ];
        message = "services.nix-p2p.libp2p.publicAllowlistPath requires at least one entry in libp2p.libp2pTrustedPublicKeys; without a trusted narinfo-signing key nothing can be proven public and every announce would be refused.";
      }
      {
        # announce-after-fetch needs the serve axis (a provider) to advertise what it fetched.
        assertion = !wantsAnnounceAfterFetch || isProvider;
        message = "services.nix-p2p.libp2p.announceAfterFetch requires a provider profile (lan-share/public-share) or libp2p.provider = true.";
      }
      {
        # A give/consume profile is inert unless the libp2p node is enabled - refuse the silent no-op.
        assertion = profile == "upstream-only" || lcfg.enable;
        message = "services.nix-p2p.libp2p.profile = \"${profile}\" requires libp2p.enable = true (and a package that speaks the libp2p flags). upstream-only is the only profile that needs no libp2p node.";
      }
      {
        # TASK-241: a router carries NO content - it cannot also be a provider/leech/announce/allowlist
        # (a router that serves would be a give-side backdoor). Mirrors the daemon's RouterServes.
        assertion = !isRouter || !(isProvider || isLeech || wantsAnnounceAfterFetch || lcfg.publicAllowlistPath != null);
        message = "services.nix-p2p.libp2p: a router (profile = \"router\" / libp2p.router) is a kad-server + relay that carries NO content; it cannot be combined with a provider profile, leech, announceAfterFetch, or a public allowlist. Choose one participation mode.";
      }
      {
        # TASK-241: a router must BIND a transport (it is a bootstrap/relay root others dial).
        assertion = !isRouter || lcfg.listen != [ ];
        message = "services.nix-p2p.libp2p: a router (profile = \"router\") requires libp2p.listen (it binds a kad-server + relay that others dial as a bootstrap/relay root).";
      }
    ];

    systemd.services.nix-p2p-daemon = {
      description = "nix-p2p decentralized binary cache daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # A libp2p PROVIDER serving real store paths (`--libp2p-provide-store`)
      # regenerates each NAR on demand via `nix-store --dump`, so nix must be on
      # the service PATH. Only when libp2p is enabled; the wave-1 HTTP service
      # spawns nothing.
      path = lib.optionals lcfg.enable [ config.nix.package ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "--listen"
            "127.0.0.1:${toString cfg.port}"
            "--upstream"
            cfg.upstream
          ]
          # TASK-29: the narinfo cache is default-on. A concrete dir passes
          # `--narinfo-cache-dir`; `null` is an explicit opt-out that passes
          # `--no-narinfo-cache` (never relying on the daemon's built-in default,
          # since $HOME under DynamicUser is not a dependable write target).
          ++ (
            if cfg.narinfoCacheDir != null then
              [ "--narinfo-cache-dir" cfg.narinfoCacheDir ]
            else
              [ "--no-narinfo-cache" ]
          )
          # libp2p P2P node flags (TASK-207). Empty unless `libp2p.enable`, so the
          # wave-1 HTTP-only service is byte-identical when libp2p is off. Each list
          # option expands to its repeatable flag; the scalars append when set.
          ++ lib.optionals lcfg.enable (
            # TASK-120: emit the AUTHORITATIVE --profile so the binary's compat-shim cross-check
            # (derive_from_flags MUST equal --profile) validates the module's own profile->flag
            # mapping end-to-end - a module mapping bug becomes a fail-fast startup error, not a
            # silent mislabel. Kept inside the libp2p block so the wave-1 HTTP-only ExecStart is
            # byte-identical when libp2p is off (the daemon defaults to upstream-only anyway).
            [ "--profile" profile ]
            # The profile-derived give/consume flags. `isProvider`/`isLeech`/`wantsAnnounceAfterFetch`
            # fold the profile together with the low-level booleans.
            ++ lib.optionals isProvider [ "--libp2p-provider" ]
            ++ lib.optionals isLeech [ "--libp2p-leech" ]
            ++ lib.optionals isRouter [ "--libp2p-router" ]
            ++ lib.optionals wantsAnnounceAfterFetch [ "--libp2p-announce-after-fetch" ]
            ++ lib.optionals (!lcfg.relayServer) [ "--libp2p-no-relay-server" ]
            ++ lib.concatMap (a: [ "--libp2p-listen" a ]) lcfg.listen
            ++ lib.concatMap (a: [ "--libp2p-external-address" a ]) lcfg.externalAddresses
            ++ lib.concatMap (b: [ "--libp2p-bootstrap" b ]) lcfg.bootstrap
            ++ lib.optionals (lcfg.scope != null) [ "--libp2p-scope" lcfg.scope ]
            ++ lib.optionals (lcfg.identitySeed != null) [ "--libp2p-identity-seed" lcfg.identitySeed ]
            ++ lib.optionals (lcfg.stateDir != null) [ "--libp2p-state-dir" lcfg.stateDir ]
            ++ lib.concatMap (s: [ "--libp2p-provide-store" s ]) lcfg.provideStore
            ++ lib.concatMap (s: [ "--libp2p-seed-nar" s ]) lcfg.seedNar
            ++ lib.optionals lcfg.printPeerAddress [ "--libp2p-print-peer-address" ]
            ++ lib.optionals (lcfg.publicAllowlistPath != null) [ "--libp2p-public-allowlist-path" lcfg.publicAllowlistPath ]
            ++ lib.concatMap (k: [ "--libp2p-trusted-public-key" k ]) lcfg.libp2pTrustedPublicKeys
            ++ lib.concatMap (n: [ "--libp2p-prove-public-narinfo" n ]) lcfg.provePublicNarinfo
          )
        );
        # A crashing daemon must never wedge the box: on-failure restart, and
        # the substituter wiring below keeps builds working via the fallback
        # while it is down (the S2 additive invariant).
        Restart = "on-failure";
        RestartSec = 1;
        # No ambient privilege: the daemon only opens a loopback socket and an
        # outbound HTTP connection.
        DynamicUser = true;
        # A private, non-world-writable /var/lib/nix-p2p owned 0700 by the
        # DynamicUser: home for the default narinfo disk cache (TASK-29, on by
        # default) AND, when libp2p is enabled, the node's durable state + the
        # public-NAR allowlist (whose anti-tamper check refuses a world-writable
        # parent). Always present now - the wave-1 HTTP service needs it for the
        # default narinfo cache dir - UNLESS the operator has turned the cache off
        # (narinfoCacheDir = null) and libp2p is disabled, in which case no state
        # dir is required at all.
        StateDirectory = lib.mkIf (cfg.narinfoCacheDir != null || lcfg.enable) "nix-p2p";
      };
    };

    # ADDITIVE substituter wiring. These merge with the system default
    # (cache.nixos.org, priority 40); the explicit ?priority params make the
    # final ordering deterministic: daemon (10) first, fallback (50) last.
    nix.settings.substituters = [
      daemonSubstituter
      fallbackSubstituter
    ];
    nix.settings.trusted-public-keys = cfg.trustedPublicKeys;
  };
}
