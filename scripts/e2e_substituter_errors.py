"""Metadata failures must not strand Nix before a healthy second cache (TASK-308)."""

import itertools
import json
import shutil


# Runs in a NEW container/store for each arm. The root daemon reads the module's
# evaluated policy; an untrusted client cannot relax its signature enforcement.
CLIENT = r'''
import json, os, pathlib, subprocess, sys, time

target, keys, policy_name, client_version = sys.argv[1:]
policy = json.loads(pathlib.Path('/etc/nix-p2p-client-policies.json').read_text())[policy_name]
env = dict(os.environ, NIX_CONF_DIR='/run/nixconf', NIX_USER_CONF_FILES='')
env.pop('NIX_CONFIG', None)
if client_version == 'compat':
    env['PATH'] = os.path.realpath('/etc/nix-p2p-compat-nix') + '/bin:' + env['PATH']
pathlib.Path(env['NIX_CONF_DIR']).mkdir()
pathlib.Path('/nix/var/nix/daemon-socket').mkdir(parents=True, exist_ok=True)
config = """
experimental-features = nix-command flakes
sandbox = false
build-users-group =
trusted-users = root
substituters = http://127.0.0.1:8082?priority=10 http://127.0.0.1:8080?priority=50
max-jobs = 0
builders =
download-attempts = 1
connect-timeout = 1
narinfo-cache-positive-ttl = 0
narinfo-cache-negative-ttl = 0
"""
config += 'fallback = ' + str(policy['fallback']).lower() + '\n'
config += 'require-sigs = ' + str(policy['requireSigs']).lower() + '\n'
config += 'trusted-public-keys = ' + keys + '\n'
pathlib.Path('/run/nixconf/nix.conf').write_text(config)
client_env = dict(env, NIX_REMOTE='daemon', HOME='/tmp', XDG_CACHE_HOME='/tmp/client-cache')
def run(argv, *, command_env=None, **kw):
    try:
        return subprocess.run(argv, env=env if command_env is None else command_env,
                              capture_output=True, text=True, timeout=90, **kw)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f'{argv}: exit {error.returncode}: {error.stderr}') from error
resolved = json.loads(run(['nix', 'config', 'show', '--json'], check=True).stdout)
versions = {name: run([name, '--version'], check=True).stdout.strip()
            for name in ['nix', 'nix-store', 'nix-daemon']}
versions['untrusted-nix-store'] = run(
    ['setpriv', '--reuid', '1000', '--regid', '1000', '--clear-groups',
     'nix-store', '--version'], command_env=client_env, check=True).stdout.strip()
before = run(['nix-store', '--check-validity', target])
assert before.returncode != 0 and 'is not valid' in before.stderr, before.stderr
assert not pathlib.Path(target).exists(), 'target already physically present'
log = open('/tmp/nix-daemon.log', 'w+')
daemon = subprocess.Popen(['nix-daemon'], env=env, stdout=log, stderr=log)
try:
    for _ in range(200):
        assert daemon.poll() is None, 'nix-daemon exited'
        if pathlib.Path('/nix/var/nix/daemon-socket/socket').exists():
            break
        time.sleep(0.05)
    else:
        raise RuntimeError('nix-daemon never became ready')
    client = subprocess.run(
        ['setpriv', '--reuid', '1000', '--regid', '1000', '--clear-groups',
         'nix-store', '--realise', target],
        env=client_env,
        capture_output=True, text=True, timeout=90)
    valid = run(['nix-store', '--check-validity', target])
    narhash = run(['nix-store', '-q', '--hash', target])
    log.flush()
    log.seek(0)
    print(json.dumps({
        'versions': versions,
        'settings': {k: resolved[k]['value'] for k in
                     ['fallback', 'require-sigs', 'max-jobs', 'builders', 'substituters']},
        'rc': client.returncode, 'stderr': client.stderr,
        'valid': valid.returncode == 0, 'validity_error': valid.stderr,
        'narhash': narhash.stdout.strip(), 'daemon_log': log.read(),
    }))
finally:
    daemon.terminate()
    daemon.wait(timeout=10)
'''


def scenario_substituter_errors(ctx, expect):
    from e2e_harness import (
        HOST_DAEMON,
        PROJECT_LABEL,
        Pod,
        build_tamper_tree,
        http_get,
        run,
    )

    fixtures = ctx.fixtures

    def client(pod, policy, target, client_version):
        result = run(
            [
                ctx.podman,
                "run",
                "--rm",
                "--pod",
                pod.pod,
                "--label",
                PROJECT_LABEL,
                ctx.image,
                "python3",
                "-c",
                CLIENT,
                target,
                fixtures.public_key,
                policy,
                client_version,
            ],
            timeout=120,
        )
        evidence = json.loads(result.stdout)
        evidence["arm"] = f"{pod.pod}/{client_version}/{policy}"
        print("substituter-errors: " + json.dumps(evidence, sort_keys=True))
        expected_version = "2.31.2" if client_version == "compat" else "2.34.8"
        expect(
            all(
                value.endswith(" " + expected_version)
                for value in evidence["versions"].values()
            ),
            f"client and daemon both use Nix {expected_version}",
            str(evidence["versions"]),
        )
        expect(evidence["settings"]["require-sigs"] is True, "signature checks enabled")
        expect(evidence["settings"]["max-jobs"] == 0, "local builds disabled")
        expect(evidence["settings"]["builders"] == "", "remote builds disabled")
        if not evidence["valid"]:
            expect(
                "is not valid" in evidence["validity_error"],
                "absence confirmed by Nix, not an operational query error",
                evidence["validity_error"],
            )
        return evidence

    # 404 control: a received upstream absence must remain 404. A 503 is an
    # actual HTTP response; connection reset forces the daemon's own 502 path.
    for status, fault in (
        (404, "http_error=404&http_error_kind=narinfo"),
        (503, "http_error=503&http_error_kind=narinfo"),
        (502, "connection_reset=narinfo"),
    ):
        with Pod(
            ctx,
            f"metadata-{status}",
            fixtures.cache,
            True,
            expect,
            daemon_binary="/bin/daemon-libp2p",
            daemon_extra_args=("--profile", "upstream-only"),
        ) as pod:
            missing, _ = http_get(f"http://127.0.0.1:{HOST_DAEMON}/{'0' * 32}.narinfo")
            expect(missing == 404, "genuine upstream miss stays 404", str(missing))
            pod.proxy_faults(fault)
            target = fixtures.store_path("lib")
            narinfo = target.rsplit("/", 1)[-1][:32] + ".narinfo"
            code, _ = http_get(f"http://127.0.0.1:{HOST_DAEMON}/{narinfo}")
            expect(code == status, f"fault produces HTTP {status}", str(code))
            for client_version, policy in itertools.product(
                ("compat", "current"), ("disabled", "optOut", "enabled")
            ):
                previous_log = pod.logs("origin")
                evidence = client(pod, policy, target, client_version)
                origin_log = pod.logs("origin")[len(previous_log) :]
                nar_served = any(
                    f"GET /{fixtures.entry('lib')['url']} HTTP/" in line
                    and '" 200 ' in line
                    for line in origin_log.splitlines()
                )
                if client_version == "compat" and policy != "enabled" and status != 404:
                    expect(evidence["settings"]["fallback"] is False, "baseline policy")
                    expect(
                        evidence["rc"] != 0,
                        f"{client_version}/{status}/{policy}: baseline bites",
                    )
                    expect(not evidence["valid"], "baseline target remains invalid")
                    expect(not nar_served, "baseline second cache served no payload")
                    expect(
                        f"GET /{narinfo} " not in origin_log,
                        "baseline did not query target at second cache",
                    )
                    expect(
                        str(status) in evidence["stderr"], "failure names HTTP status"
                    )
                else:
                    expect(
                        evidence["rc"] == 0,
                        f"{client_version}/{status}/{policy}: Nix realizes target",
                    )
                    expect(evidence["valid"], "realized target is valid")
                    expect(
                        evidence["narhash"] == fixtures.nar_hash("lib"),
                        "realized NarHash matches signed fixture",
                    )
                    expect(nar_served, "healthy second cache served payload")
                    expect(
                        f"GET /{narinfo} " in origin_log,
                        "healthy second cache served metadata",
                    )

    # The second cache is the only working metadata source here. Falling back
    # must not bless an untrusted signature or mismatched signed NarHash.
    for kind, reason in (
        ("foreign-key", "not signed by any of the keys"),
        ("narhash", "hash mismatch"),
    ):
        scratch = ctx.scratch / f"metadata-fallback-{kind}"
        if scratch.exists():
            shutil.rmtree(scratch)
        cache = build_tamper_tree(fixtures, scratch, kind)
        with Pod(
            ctx,
            f"metadata-{kind}",
            cache,
            True,
            expect,
            daemon_binary="/bin/daemon-libp2p",
            daemon_extra_args=("--profile", "upstream-only"),
        ) as pod:
            pod.proxy_faults("http_error=503&http_error_kind=narinfo")
            previous_log = pod.logs("origin")
            evidence = client(pod, "enabled", fixtures.store_path("app"), "compat")
            origin_log = pod.logs("origin")[len(previous_log) :]
            expect(evidence["rc"] != 0, f"fallback rejects {kind}")
            expect(not evidence["valid"], "tampered target remains invalid")
            expect(reason in evidence["stderr"], "specific trust/integrity rejection")
            target_hash = fixtures.store_path("app").rsplit("/", 1)[-1][:32]
            expect(
                any(
                    f"GET /{target_hash}.narinfo HTTP/" in line and '" 200 ' in line
                    for line in origin_log.splitlines()
                ),
                "negative arm queries target metadata at second cache",
            )
