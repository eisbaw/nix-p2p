# Systemd interface confinement must not strand the HTTP upstream (TASK-308.3).
# HTTP is intentional: production TLS uses WebPKI roots, so a hermetic test CA
# cannot be installed without changing product trust. This tests the actual
# scheme-independent kernel interface boundary; TLS verification stays intact.
{ pkgs, daemonLibp2p }:
let
  inherit (pkgs) lib;
  key = pkgs.runCommand "upstream-routing-test-key" { nativeBuildInputs = [ pkgs.nix ]; } ''
    export NIX_STATE_DIR="$TMPDIR/state" NIX_CONF_DIR="$TMPDIR/conf"
    mkdir -p "$out" "$NIX_STATE_DIR" "$NIX_CONF_DIR"
    nix-store --generate-binary-cache-key routing-vm-test-1 "$out/secret" "$out/public"
  '';
  publicKey = lib.removeSuffix "\n" (builtins.readFile "${key}/public");
  upstream = "http://10.90.2.3:5000";
  primary = "http://127.0.0.1:8082";
  clientModule = address: { ... }: {
    imports = [ ./nix-p2p.nix ];
    networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.1.${address}"; prefixLength = 24; }];
    networking.interfaces.eth2.ipv4.addresses = [{ address = "10.90.2.${address}"; prefixLength = 24; }];
    services.nix-p2p = {
      enable = true;
      package = daemonLibp2p;
      inherit upstream;
      narinfoCacheDir = null;
      trustedPublicKeys = [ publicKey ];
      libp2p = {
        enable = true;
        profile = "lan-share";
        listen = [ "/ip4/10.90.1.${address}/tcp/4001" ];
        mdns = true;
        announceAfterFetch = true;
        printPeerAddress = true;
      };
    };
    systemd.services.nix-p2p-daemon.serviceConfig.RestrictNetworkInterfaces = [ "lo" "eth1" ];
    # Positive realization has no second cache that could hide a broken primary.
    nix.settings = {
      substituters = lib.mkForce [ primary ];
      trusted-public-keys = lib.mkForce [ publicKey ];
      require-sigs = true;
      max-jobs = 0;
      builders = lib.mkForce "";
      download-attempts = 1;
      narinfo-cache-negative-ttl = 0;
      narinfo-cache-positive-ttl = 0;
    };
    users.users.alice = { isNormalUser = true; };
  };
in
pkgs.testers.runNixOSTest {
  name = "nix-p2p-upstream-routing";
  defaults = { ... }: {
    virtualisation = { writableStore = true; vlans = [ 1 2 ]; memorySize = 1024; };
    networking.firewall.enable = false;
    environment.systemPackages = [ pkgs.curl pkgs.netcat-openbsd ];
  };
  nodes = {
    legacy = clientModule "1";
    # Only this client uses the helper; legacy retains direct upstream egress.
    client = { ... }: {
      imports = [ (clientModule "2") ];
      services.nix-p2p.upstreamRelay.enable = true;
    };
    origin = { ... }: {
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.1.3"; prefixLength = 24; }];
      networking.interfaces.eth2.ipv4.addresses = [{ address = "10.90.2.3"; prefixLength = 24; }];
      virtualisation.additionalPaths = [ key pkgs.bash pkgs.coreutils ];
      services.nix-serve = { enable = true; port = 5000; secretKeyFile = "/run/routing-cache.sec"; };
      systemd.services.nix-serve.wantedBy = lib.mkForce [ ];
    };
  };
  testScript = ''
    import json
    import shlex
    import time

    start_all()
    origin.succeed("cp ${key}/secret /run/routing-cache.sec; chmod 644 /run/routing-cache.sec; systemctl start nix-serve")
    origin.wait_for_unit("nix-serve.service")
    origin.wait_for_open_port(5000)
    for node in [legacy, client]:
        node.wait_for_unit("nix-p2p-daemon.service")
        node.wait_until_succeeds("curl -fsS ${primary}/nix-cache-info")
        node.succeed("curl -fsS ${upstream}/nix-cache-info")

    # Runtime outputs belong only to origin's writable store, not the host's
    # shared read-only store. Neither consumer can register pre-existing bytes.
    def payload(name):
        expression = (
            'derivation { name = "' + name + '"; system = "${pkgs.stdenv.hostPlatform.system}"; '
            'builder = (builtins.storePath "${pkgs.bash}") + "/bin/bash"; '
            'args = [ "-c" "mkdir -p $out; printf %s ' + name + ' > $out/data" ]; '
            'PATH = (builtins.storePath "${pkgs.coreutils}") + "/bin"; }'
        )
        # Input-addressed runtime output: signature trust is required, unlike
        # nix-store --add (content-addressed). Never copy output bytes to clients.
        return origin.succeed(
            "nix-build --no-out-link --option substituters " + shlex.quote("") +
            " --expr " + shlex.quote(expression)
        ).strip()

    target = payload("routing-primary")
    fallback_target = payload("routing-fallback")
    foreign_target = payload("routing-foreign")
    narinfo = target.rsplit("/", 1)[1][:32] + ".narinfo"
    expected_hash = origin.succeed(f"nix-store -q --hash {target}").strip()
    for node in [legacy, client]:
        node.succeed(f"test ! -e {target}")
        status, error = node.execute(f"nix-store --check-validity {target} 2>&1")
        assert status != 0 and "is not valid" in error, error

    with subtest("old confinement blocks primary although upstream is healthy"):
        code = legacy.succeed(
            f"curl --max-time 15 -sS -o /tmp/legacy-body -w '%{{http_code}}' ${primary}/{narinfo}"
        ).strip()
        assert code == "502", code
        legacy.succeed("grep -Fx 'upstream unavailable' /tmp/legacy-body")
        status, output = legacy.execute(f"timeout 20 su - alice -c 'nix-store --realise {target}' 2>&1")
        assert status != 0 and "502" in output, output
        legacy.succeed(f"test ! -e {target}")

    with subtest("confined primary promptly reaches routed upstream"):
        begin = time.monotonic_ns()
        code = client.succeed(
            f"curl --max-time 10 -sS -o /tmp/primary-narinfo -w '%{{http_code}}' ${primary}/{narinfo}"
        ).strip()
        elapsed_ms = (time.monotonic_ns() - begin) // 1_000_000
        print(json.dumps({"primary_status": code, "metadata_elapsed_ms": elapsed_ms}))
        assert code == "200", f"primary must work without direct fallback: {code}"
        assert elapsed_ms < 2000, f"primary metadata stalled: {elapsed_ms}ms"
        client.succeed("systemctl is-active nix-p2p-upstream.service")
        begin = time.monotonic_ns()
        output = client.succeed(f"su - alice -c 'nix-store --realise {target}' 2>&1")
        elapsed_ms = (time.monotonic_ns() - begin) // 1_000_000
        print(json.dumps({"realization_elapsed_ms": elapsed_ms, "output": output}))
        assert "502" not in output and "retrying" not in output, output
        assert elapsed_ms < 5000, f"small signed realization stalled: {elapsed_ms}ms"
        assert client.succeed(f"nix-store -q --hash {target}").strip() == expected_hash
        client.succeed(f"nix-store --verify-path {target}")
        assert client.succeed(f"cat {target}/data") == origin.succeed(f"cat {target}/data")
        for unit in ["nix-p2p-daemon", "nix-p2p-upstream"]:
            client.succeed(f"journalctl -u {unit} --no-pager | grep 'substituted path=/nar/'")
        client.succeed("journalctl -u nix-p2p-upstream --no-pager | grep 'operator profile=upstream-only'")
        client.fail("systemctl cat nix-p2p-upstream | grep -E -- '--libp2p-|--lan-signing-key'")

    with subtest("peer interface boundary survives routed HTTP access"):
        allowed = client.succeed("systemctl show nix-p2p-daemon -p RestrictNetworkInterfaces --value").split()
        assert set(allowed) == {"lo", "eth1"}, allowed
        # Same live peer listener: allowed LAN ingress works. Force its route
        # over the excluded interface to prove it is the boundary, not a dead
        # listener or a public-address classification that rejects the probe.
        origin.succeed("nc -z -w 2 -s 10.90.1.3 10.90.1.2 4001")
        origin.succeed("ip route add 10.90.1.2/32 via 10.90.2.2 dev eth2")
        origin.fail("nc -z -w 2 -s 10.90.2.3 10.90.1.2 4001")
        origin.succeed("ip route del 10.90.1.2/32")
        origin.succeed("nc -z -w 2 -s 10.90.1.3 10.90.1.2 4001")

    with subtest("foreign signatures remain rejected through the routed primary"):
        origin.succeed("nix-store --generate-binary-cache-key foreign-vm-test-1 /tmp/foreign.sec /tmp/foreign.pub")
        origin.succeed("cp /tmp/foreign.sec /run/routing-cache.sec; chmod 644 /run/routing-cache.sec; systemctl restart nix-serve")
        origin.wait_for_unit("nix-serve.service")
        origin.wait_for_open_port(5000)
        foreign_narinfo = foreign_target.rsplit("/", 1)[1][:32] + ".narinfo"
        client.succeed(f"test ! -e {foreign_target}")
        metadata = client.succeed(f"curl -fsS ${primary}/{foreign_narinfo}")
        assert "Sig: foreign-vm-test-1:" in metadata, metadata
        status, output = client.execute(f"su - alice -c 'nix-store --realise {foreign_target}' 2>&1")
        assert status != 0 and "signed by any of the keys" in output, output
        client.succeed(f"test ! -e {foreign_target}")
        client.fail(f"nix-store --check-validity {foreign_target}")
        origin.succeed("cp ${key}/secret /run/routing-cache.sec; chmod 644 /run/routing-cache.sec; systemctl restart nix-serve")
        origin.wait_for_unit("nix-serve.service")
        origin.wait_for_open_port(5000)

    with subtest("upstream service outage keeps peers alive and permits direct fallback"):
        client.succeed("systemctl stop nix-p2p-upstream")
        client.succeed("systemctl is-active nix-p2p-daemon")
        client.succeed(f"test ! -e {fallback_target}")
        caches = shlex.quote("${primary}?priority=10 ${upstream}?priority=50")
        client.succeed(f"nix-store --realise {fallback_target} --option substituters {caches}")
        assert client.succeed(f"nix-store -q --hash {fallback_target}") == origin.succeed(f"nix-store -q --hash {fallback_target}")
        client.succeed("nix config show | grep -Fx 'require-sigs = true'")
  '';
}
