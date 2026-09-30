"""Real local builds across isolated LAN stores (TASK-305).

The baseline switch omits only the new configuration, so old binaries fail at
Nix realization rather than at argument parsing. No custom output or narinfo is
supplied by the harness. All containers have separate writable Nix databases.
"""

import json
import os
import shlex
import time
import uuid


def scenario_lan_custom_private_bootstrap(ctx, expect):
    scenario_lan_custom(ctx, expect, private_bootstrap=True)


def scenario_lan_custom(ctx, expect, private_bootstrap=False):
    from e2e_harness import (
        LIBP2P_BOOT_PEER_ID,
        LIBP2P_BOOT_SEED_HEX,
        PROJECT_LABEL,
        run,
    )

    baseline = os.environ.get("NIX_P2P_LAN_CUSTOM_BASELINE") == "1"
    name = "nix-p2p-custom-" + uuid.uuid4().hex[:10]
    network = name + "-net"
    roles = ("producer", "consumer", "untrusted")
    nodes = {role: name + "-" + role for role in roles}
    ips = {role: f"10.211.35.{10 + i}" for i, role in enumerate(roles)}
    if private_bootstrap:
        nodes["bootstrap"] = name + "-bootstrap"
        ips["bootstrap"] = "10.211.35.20"
    pm = ctx.podman

    def execute(role, *args, check=True, timeout=120):
        return run([pm, "exec", nodes[role], *args], check=check, timeout=timeout)

    def logs(role):
        return execute(role, "cat", "/tmp/daemon.log", check=False).stdout

    def mdns_disabled(role):
        output = logs(role)
        return not any(
            marker in output
            for marker in (
                "LAN discovery ACTIVE via mDNS",
                "DISCOVERY-LATENCY-MDNS",
            )
        )

    def await_mdns(*waiting_roles):
        if private_bootstrap:
            for role in waiting_roles:
                if not mdns_disabled(role):
                    raise RuntimeError(f"unexpected mDNS discovery: {logs(role)}")
            return
        deadline = time.monotonic() + 45
        pending = set(waiting_roles)
        while pending and time.monotonic() < deadline:
            for role in tuple(pending):
                if "DISCOVERY-LATENCY-MDNS first LAN peer discovered" in logs(role):
                    pending.remove(role)
            if pending:
                time.sleep(0.5)
        if pending:
            detail = "\n".join(f"{role}: {logs(role)}" for role in sorted(pending))
            raise RuntimeError(f"mDNS discovery did not become ready: {detail}")

    def start(role, key, share=True, record_ttl=12):
        argv = [
            "/bin/daemon-libp2p",
            "--profile",
            "lan-share",
            "--listen",
            "127.0.0.1:8082",
            "--upstream",
            "http://127.0.0.1:8081",
            "--libp2p-listen",
            f"/ip4/{ips[role]}/tcp/0",
            "--libp2p-state-dir",
            "/tmp/peer-state",
            "--libp2p-announce-after-fetch",
            "--libp2p-record-ttl-secs",
            str(record_ttl),
        ]
        if private_bootstrap:
            argv += [
                "--libp2p-no-mdns",
                "--libp2p-bootstrap",
                f"{LIBP2P_BOOT_PEER_ID}@/ip4/{ips['bootstrap']}/tcp/4001",
            ]
        if not baseline:
            argv += ["--lan-trusted-public-key", key]
            if role == "producer" and share:
                argv += [
                    "--lan-share-custom-builds",
                    "--lan-signing-key-file",
                    "/tmp/pool.sec",
                ]
        # The background process lives inside a disposable container, and its
        # stdout/stderr are retained and inspected below.
        execute(
            role,
            "bash",
            "-c",
            "RUST_LOG=info "
            + shlex.join(argv)
            + " >/tmp/daemon.log 2>&1 & echo $! >/tmp/daemon.pid",
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            response = execute(
                role,
                "python3",
                "-c",
                "import urllib.request; urllib.request.urlopen("
                "'http://127.0.0.1:8082/nix-cache-info',timeout=1)",
                check=False,
            )
            if response.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(f"{role} failed startup: {logs(role)}")

    def stop_daemon(role):
        execute(role, "bash", "-c", 'kill "$(cat /tmp/daemon.pid)"')
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = execute(
                role,
                "bash",
                "-c",
                'kill -0 "$(cat /tmp/daemon.pid)" 2>/dev/null',
                check=False,
            )
            # The container init may retain a zombie, but the listener must close.
            probe = execute(
                role,
                "python3",
                "-c",
                "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',8082))",
                check=False,
            )
            if status.returncode != 0 or probe.returncode != 0:
                return
            time.sleep(0.1)
        raise RuntimeError(f"{role} did not stop")

    def realize(role, drv, key, cache_name="default"):
        return execute(
            role,
            "env",
            f"XDG_CACHE_HOME=/tmp/nix-client-cache-{cache_name}",
            "nix-store",
            "--realise",
            drv,
            "--option",
            "substituters",
            "http://127.0.0.1:8082",
            "--option",
            "trusted-public-keys",
            key,
            "--option",
            "require-sigs",
            "true",
            "--option",
            "narinfo-cache-negative-ttl",
            "0",
            "--option",
            "narinfo-cache-positive-ttl",
            "3600",
            "--option",
            "max-jobs",
            "0",
            "--option",
            "builders",
            "",
            check=False,
        )

    try:
        # No public egress is possible, including from the daemon. The only
        # configured upstream is an empty LOCAL cache, never a metadata fixture.
        run(
            [
                pm,
                "network",
                "create",
                "--internal",
                "--subnet",
                "10.211.35.0/24",
                "--label",
                PROJECT_LABEL,
                network,
            ]
        )
        for role in nodes:
            run(
                [
                    pm,
                    "run",
                    "-d",
                    "--name",
                    nodes[role],
                    "--network",
                    network,
                    "--ip",
                    ips[role],
                    "--label",
                    PROJECT_LABEL,
                    ctx.image,
                    "sleep",
                    "infinity",
                ]
            )

        if private_bootstrap:
            # A content-free router supplies only the private DHT entry point.
            # No content/provider address is injected into a consumer. Disabling
            # mDNS on EVERY process makes this a static-discovery regression,
            # not a claim that this same-bridge test emulates WireGuard itself.
            execute(
                "bootstrap",
                "bash",
                "-c",
                "RUST_LOG=info "
                + shlex.join(
                    [
                        "/bin/daemon-libp2p",
                        "--profile",
                        "router",
                        "--libp2p-router",
                        "--listen",
                        "127.0.0.1:8082",
                        "--upstream",
                        "http://127.0.0.1:8081",
                        "--libp2p-no-mdns",
                        "--libp2p-no-relay-server",
                        "--libp2p-scope",
                        "lan-share.v1",
                        "--libp2p-listen",
                        f"/ip4/{ips['bootstrap']}/tcp/4001",
                        "--libp2p-identity-seed",
                        LIBP2P_BOOT_SEED_HEX,
                    ]
                )
                + " >/tmp/daemon.log 2>&1 & echo $! >/tmp/daemon.pid",
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                probe = execute(
                    "bootstrap",
                    "python3",
                    "-c",
                    "import urllib.request; urllib.request.urlopen("
                    "'http://127.0.0.1:8082/nix-cache-info',timeout=1)",
                    check=False,
                )
                if probe.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"bootstrap failed startup: {logs('bootstrap')}")

        execute(
            "producer",
            "nix-store",
            "--generate-binary-cache-key",
            "lan-test-1",
            "/tmp/pool.sec",
            "/tmp/pool.pub",
        )
        key = execute("producer", "cat", "/tmp/pool.pub").stdout.strip()
        execute(
            "untrusted",
            "nix-store",
            "--generate-binary-cache-key",
            "foreign-1",
            "/tmp/foreign.sec",
            "/tmp/foreign.pub",
        )
        foreign = execute("untrusted", "cat", "/tmp/foreign.pub").stdout.strip()
        # Only the PUBLIC half crosses nodes. The secret never leaves A.
        for role in roles:
            execute(role, "mkdir", "/tmp/empty-cache")
            execute(
                role,
                "bash",
                "-c",
                "python3 -m http.server 8081 --bind 127.0.0.1 --directory /tmp/empty-cache >/tmp/upstream.log 2>&1 &",
            )
            start(role, key)

        bash = execute("producer", "readlink", "-f", "/bin/bash").stdout.strip()
        bash_root = bash.rsplit("/bin/", 1)[0]
        marker = "LAN_CUSTOM_" + uuid.uuid4().hex
        expected_content = marker + "\n" + bash_root + "\n"
        expr = (
            "derivation { name = " + json.dumps(marker.lower()) + "; "
            'system = "x86_64-linux"; builder = "${builtins.storePath '
            + json.dumps(bash_root)
            + '}/bin/bash"; args = [ "-c" '
            + json.dumps(
                "echo invoked >/tmp/custom-builder-invoked; "
                + "printf '%s\\n%s\\n' "
                + marker
                + " "
                + bash_root
                + ' >"$out"'
            )
            + " ]; }"
        )
        derivations = {}
        for role in roles:
            execute(role, "nix-store", "--check-validity", bash_root)
            derivations[role] = execute(
                role, "nix-instantiate", "--expr", expr
            ).stdout.strip()
        expect(
            len(set(derivations.values())) == 1,
            "custom LAN: identical derivation and registered builder inputs",
        )
        drv = derivations["producer"]
        output = execute(
            "producer", "nix-store", "--query", "--outputs", drv
        ).stdout.strip()
        store_hash = output.rsplit("/", 1)[1].split("-", 1)[0]
        for role in roles:
            expect(
                execute(role, "test", "!", "-e", output, check=False).returncode == 0,
                f"custom LAN: {role} starts without output",
            )

        # Build AFTER daemon startup. No seed, static store provision, restart,
        # fetched event, or direct copy can account for this supply.
        built = execute(
            "producer",
            "nix-store",
            "--realise",
            drv,
            "--option",
            "substitute",
            "false",
            "--option",
            "builders",
            "",
        )
        expect(
            built.returncode == 0,
            "custom LAN: producer builds once with substitution disabled",
        )
        expect(
            execute("producer", "cat", output).stdout == expected_content,
            "custom LAN: producer content matches runtime nonce",
        )
        execute("producer", "test", "-f", "/tmp/custom-builder-invoked")
        # Observe profile-default discovery without injecting addresses or making
        # a metadata request. Leave the first custom lookup until after libp2p's
        # 60-second idle connection interval: discovery must still work then.
        await_mdns(*roles)
        if private_bootstrap:
            expect(
                all(mdns_disabled(r) for r in nodes),
                "custom private bootstrap: mDNS disabled on every process",
            )
        idle_until = time.monotonic() + 65
        print("CUSTOM-LAN-IDLE: first custom lookup after 65 seconds idle", flush=True)
        while time.monotonic() < idle_until:
            time.sleep(max(0, min(1, idle_until - time.monotonic())))
        if private_bootstrap:
            await_mdns(*nodes)

        if baseline:
            probe = (
                "import urllib.request, urllib.error\n"
                "try:\n"
                " urllib.request.urlopen('http://127.0.0.1:8082/"
                + store_hash
                + ".narinfo')\n"
                "except urllib.error.HTTPError as e:\n"
                " print(e.code)\n"
            )
            for role in ("producer", "consumer"):
                status = execute(role, "python3", "-c", probe).stdout.strip()
                expect(
                    status == "404",
                    f"custom LAN baseline: {role} metadata is absent (404)",
                )
        realized = realize("consumer", drv, key)
        print(
            "CUSTOM-LAN-REALIZE", realized.returncode, realized.stdout, realized.stderr
        )
        expect(
            realized.returncode == 0,
            "custom LAN: consumer realizes custom drv with local and remote builds disabled",
            realized.stderr,
        )
        # Keep baseline's real failure attributable; don't replace it with cat's
        # missing-file error or claim that the absence of an output is success.
        if realized.returncode != 0:
            if baseline:
                expect(
                    realized.returncode == 100
                    and "local builds are disabled" in realized.stderr.lower(),
                    "custom LAN baseline: failure is missing substitution with builds disabled",
                    realized.stderr,
                )
                execute("consumer", "test", "!", "-e", output)
                execute("consumer", "test", "!", "-e", "/tmp/custom-builder-invoked")
            for role in roles:
                print(f"CUSTOM-LAN-LOG {role}\n{logs(role)}")
            return
        expect(
            execute("consumer", "cat", output).stdout == expected_content,
            "custom LAN: consumer bytes match freshly built content",
        )
        execute("consumer", "test", "!", "-e", "/tmp/custom-builder-invoked")
        hashes = [
            execute(role, "nix-store", "--query", "--hash", output).stdout.strip()
            for role in ("producer", "consumer")
        ]
        expect(
            ".narinfo" not in execute("consumer", "cat", "/tmp/upstream.log").stdout,
            "custom LAN: no upstream metadata dependency",
        )
        expect(
            hashes[0] == hashes[1], "custom LAN: producer and consumer NarHash match"
        )
        expect(
            "two-pass bounded Bao regeneration completed" in logs("producer"),
            "custom LAN: producer completed actual libp2p store-backed payload serve",
            logs("producer"),
        )

        refs = execute(
            "consumer", "nix-store", "--query", "--references", output
        ).stdout.split()
        expect(
            bash_root in refs, "custom LAN: Nix verifies non-empty signed References"
        )
        # Both Nix's positive cache (TTL 3600) and daemon metadata stay warm.
        # Verify the actual Nix cache exists before preserving it across restart.
        execute(
            "consumer",
            "python3",
            "-c",
            "from pathlib import Path; "
            "assert list(Path('/tmp/nix-client-cache-default').rglob('binary-cache-*.sqlite'))",
        )
        # Only remove the realized output from B, never its metadata caches.
        execute("consumer", "nix-store", "--delete", output)
        time.sleep(15)  # beyond the initial 12-second provider-record expiry
        renewed = realize("consumer", drv, key)
        expect(
            renewed.returncode == 0,
            "custom LAN: warm metadata works after original claim expiry",
            renewed.stderr,
        )
        execute("consumer", "nix-store", "--delete", output)
        stop_daemon("producer")
        stop_daemon("consumer")
        start("producer", key)
        start("consumer", key)
        await_mdns("producer", "consumer")
        restored = realize("consumer", drv, key)
        expect(
            restored.returncode == 0,
            "custom LAN: producer supply survives restart with warm Nix and daemon metadata",
            restored.stderr,
        )
        expect(
            "LAN custom metadata published with verified store supply"
            not in logs("producer"),
            "custom LAN: restart realization uses persisted supply without regenerating metadata",
            logs("producer"),
        )
        # Different store paths can contain byte-identical NARs. Admit both,
        # retain Nix's metadata, then restart A and GC its most recently admitted
        # backing path. The remaining alias must still supply the shared NarHash.
        aliases = []
        for suffix in ("alias_a", "alias_b"):
            alias_expr = expr.replace(
                json.dumps(marker.lower()), json.dumps(marker.lower() + "_" + suffix), 1
            ).replace(marker, marker + "_ALIAS")
            alias_drvs = [
                execute(role, "nix-instantiate", "--expr", alias_expr).stdout.strip()
                for role in ("producer", "consumer")
            ]
            expect(
                alias_drvs[0] == alias_drvs[1],
                "custom LAN: alias derivation inputs agree",
            )
            alias_drv = alias_drvs[0]
            alias_out = execute(
                "producer", "nix-store", "--query", "--outputs", alias_drv
            ).stdout.strip()
            execute(
                "producer",
                "nix-store",
                "--realise",
                alias_drv,
                "--option",
                "substitute",
                "false",
                "--option",
                "builders",
                "",
            )
            alias_result = realize("consumer", alias_drv, key)
            expect(
                alias_result.returncode == 0,
                "custom LAN: admits equal-NAR alias",
                alias_result.stderr,
            )
            execute("consumer", "nix-store", "--delete", alias_out)
            aliases.append((alias_drv, alias_out))
        alias_hashes = [
            execute("producer", "nix-store", "--query", "--hash", path).stdout.strip()
            for _, path in aliases
        ]
        expect(
            aliases[0][1] != aliases[1][1] and alias_hashes[0] == alias_hashes[1],
            "custom LAN: distinct store paths have identical NARs",
        )
        stop_daemon("producer")
        start("producer", key)
        await_mdns("producer")
        execute("producer", "nix-store", "--delete", aliases[1][1])
        time.sleep(15)
        survivor = realize("consumer", aliases[0][0], key)
        expect(
            survivor.returncode == 0,
            "custom LAN: alias supply survives restart and GC of another equal-NAR path",
            survivor.stderr,
        )
        expect(
            execute("consumer", "cat", aliases[0][1]).stdout
            == marker + "_ALIAS\n" + bash_root + "\n",
            "custom LAN: surviving alias content is exact",
        )
        expect(
            "LAN custom metadata published with verified store supply"
            not in logs("producer"),
            "custom LAN: alias recovery uses durable supply with warm Nix metadata",
            logs("producer"),
        )
        expect(
            "two-pass bounded Bao regeneration completed" in logs("producer"),
            "custom LAN: surviving alias is freshly served by the restarted provider",
            logs("producer"),
        )
        execute("consumer", "test", "!", "-e", "/tmp/custom-builder-invoked")

        if not baseline:
            rejected = realize("untrusted", drv, foreign)
            expect(
                rejected.returncode != 0,
                "custom LAN: Nix rejects untrusted pool signer",
            )
            expect(
                "not signed by any of the keys" in rejected.stderr.lower(),
                "custom LAN: negative fails at Nix signature verification",
                rejected.stderr,
            )
            execute("untrusted", "test", "!", "-e", output)
            execute("untrusted", "test", "!", "-e", "/tmp/custom-builder-invoked")

        # Nix now trusts A, but this daemon trusts a different authority. Changing
        # trust must also make its previous disk-cached metadata ineligible.
        stop_daemon("untrusted")
        start("untrusted", foreign)
        await_mdns("untrusted")
        # This arm tests the daemon signature gate; a separate Nix client cache
        # prevents the prior request from bypassing metadata lookup altogether.
        rejected = realize("untrusted", drv, key, cache_name="daemon-trust")
        expect(
            rejected.returncode != 0,
            "custom LAN: daemon rejects untrusted peer metadata",
            rejected.stderr,
        )
        expect(
            "LAN metadata rejected" in logs("untrusted"),
            "custom LAN: rejection occurred at daemon signature gate",
            logs("untrusted"),
        )
        execute("untrusted", "test", "!", "-e", output)

        # B is allowed to consume pool metadata, but never enabled custom
        # sharing. Re-fetch under a fresh daemon with a long enough record TTL
        # that an accidental announcement cannot expire during this control.
        execute("consumer", "nix-store", "--delete", output)
        stop_daemon("consumer")
        start("consumer", key, record_ttl=300)
        await_mdns("consumer")
        retained = realize("consumer", drv, key)
        expect(
            retained.returncode == 0,
            "custom LAN: sharing-disabled consumer obtains the custom output",
            retained.stderr,
        )
        execute("consumer", "test", "-e", output)
        stop_daemon("untrusted")
        start("untrusted", key)
        await_mdns("untrusted")
        warm = execute(
            "untrusted",
            "python3",
            "-c",
            "import urllib.request; print(urllib.request.urlopen("
            + repr(f"http://127.0.0.1:8082/{store_hash}.narinfo")
            + ",timeout=30).read().decode(),end='')",
        )
        expect(
            f"StorePath: {output}\n" in warm.stdout,
            "custom LAN: third node has valid metadata before original provider is disabled",
            warm.stdout,
        )
        stop_daemon("producer")
        start("producer", key, share=False)
        await_mdns("producer")
        declined = realize("untrusted", drv, key, cache_name="disabled-consumer")
        expect(
            declined.returncode != 0,
            "custom LAN: sharing-disabled consumer does not serve its retained custom output",
            declined.stderr,
        )
        expect(
            execute("consumer", "cat", output).stdout == expected_content,
            "custom LAN: disabled-sharing control retains the valid output on consumer B",
        )
        execute("untrusted", "test", "!", "-e", output)
        execute("untrusted", "test", "!", "-e", "/tmp/custom-builder-invoked")
        execute("consumer", "nix-store", "--delete", output)
        disabled = realize("consumer", drv, key)
        expect(
            disabled.returncode != 0,
            "custom LAN: disabling custom sharing stops serving existing output",
            disabled.stderr,
        )
        execute("consumer", "test", "!", "-e", output)
        stop_daemon("producer")
        start("producer", key)
        await_mdns("producer")
        recovered = realize("consumer", drv, key)
        expect(
            recovered.returncode == 0,
            "custom LAN: re-enabling sharing restores actual realization before tampering",
            recovered.stderr,
        )
        if recovered.returncode != 0:
            raise RuntimeError(
                f"producer did not recover before corruption arm: {logs('producer')}"
            )
        expect(
            execute("consumer", "cat", output).stdout == expected_content,
            "custom LAN: recovered bytes match original build",
        )
        execute("consumer", "nix-store", "--delete", output)
        producer_log_before_tamper = logs("producer")
        # Corrupt the producer's bytes without changing its registered NarHash.
        # No other node retains the output, so a valid alternate cannot mask it.
        execute("producer", "chmod", "u+w", output)
        execute(
            "producer",
            "python3",
            "-c",
            "from pathlib import Path; p=Path("
            + repr(output)
            + "); b=p.read_bytes(); p.write_bytes(bytes([b[0]^1])+b[1:])",
        )
        corrupted = realize("consumer", drv, key)
        expect(
            corrupted.returncode != 0,
            "custom LAN: corrupt provider payload cannot realize",
            corrupted.stderr,
        )
        corruption_log = logs("producer")[len(producer_log_before_tamper) :]
        expect(
            "two-pass regeneration failed closed" in corruption_log
            and "has root" in corruption_log
            and "refusing before STATUS_NAR" in corruption_log,
            "custom LAN: payload rejection is the provider's content-root verification",
            corruption_log,
        )
        execute("consumer", "test", "!", "-e", output)
        execute("consumer", "test", "!", "-e", "/tmp/custom-builder-invoked")
    finally:
        for role in nodes:
            run([pm, "rm", "-f", "--ignore", nodes[role]], check=False)
        run([pm, "network", "rm", "-f", network], check=False)
