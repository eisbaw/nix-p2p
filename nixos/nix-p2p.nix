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
      default = null;
      description = ''
        Optional persistent narinfo disk-cache directory (daemon task-8). Off by
        default in wave 1 so enabling it is a separate, reviewable change
        (task-29 wires a default and re-asserts the e2e AC). When set with the
        default DynamicUser sandbox the directory must be writable by the
        service - prefer a StateDirectory-managed path.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nix-p2p-daemon = {
      description = "nix-p2p decentralized binary cache daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "--listen"
            "127.0.0.1:${toString cfg.port}"
            "--upstream"
            cfg.upstream
          ]
          ++ lib.optionals (cfg.narinfoCacheDir != null) [
            "--narinfo-cache-dir"
            cfg.narinfoCacheDir
          ]
        );
        # A crashing daemon must never wedge the box: on-failure restart, and
        # the substituter wiring below keeps builds working via the fallback
        # while it is down (the S2 additive invariant).
        Restart = "on-failure";
        RestartSec = 1;
        # No ambient privilege: the daemon only opens a loopback socket and an
        # outbound HTTP connection.
        DynamicUser = true;
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
