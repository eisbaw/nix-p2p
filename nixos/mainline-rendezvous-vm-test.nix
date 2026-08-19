# TASK-258 SPIKE — hermetic KVM VM e2e for the BitTorrent Mainline peer-address rendezvous.
#
# The owner's e2e requirement (2026-08-18): two NAT'd VMs that CANNOT connect directly, a
# LOCAL Mainline DHT node on the public segment as the hermetic entry point (NOT the real
# router.bittorrent.com swarm), node A announcing first and node B booting ~10s LATER and
# discovering A via BEP5 (get_peers) despite the NAT.
#
# TOPOLOGY (the NixOS test driver assigns 192.168.<vlan>.<nodeNumber>, nodeNumber = the
# node's ALPHABETICAL index: gwa=1, gwb=2, mainline=3, nodea=4, nodeb=5):
#   vlan1 = the PUBLIC segment. `mainline` (192.168.1.3) runs the local Mainline DHT SERVER.
#   gwa   : vlans [1,2], MASQUERADEs 192.168.2.0/24  -> NATs nodea.
#   gwb   : vlans [1,3], MASQUERADEs 192.168.3.0/24  -> NATs nodeb.
#   nodea : vlan2 only (192.168.2.4), default route via gwa. Behind NAT.
#   nodeb : vlan3 only (192.168.3.5), default route via gwb. Behind NAT.
# nodea and nodeb share NO segment, so they cannot connect directly — exactly the owner ask.
#
# THE DEMONSTRATION + THE FINDING (AC#3 + AC#13). nodea's announce is MASQUERADE'd, so the
# Mainline server records nodea's peer address as gwa's PUBLIC NAT IP (192.168.1.1) + the
# announced libp2p port — NOT nodea's private 192.168.2.4. nodeb `get_peers` RECOVERS that
# entry (BEP5 discovery of membership works across the NAT: "they see each other via BEP5").
# But the recovered address is the NAT gateway IP with no inbound port mapping and carries NO
# PeerId / no /p2p-circuit — so it is UNDIALABLE. BEP5 discovers A's existence; it does NOT
# let B reach a NAT'd A. That is the spike's central finding, shown here with real NAT.
#
# Args: pkgs, rendezvousSpike (the `mainline-rendezvous` crate's `rendezvous-spike` binary).
{ pkgs, rendezvousSpike }:
let
  spike = "${rendezvousSpike}/bin/rendezvous-spike";
  ipMainline = "192.168.1.3";
  ipGwaPublic = "192.168.1.1"; # gwa's vlan1 address == the NAT public IP nodea appears as
  gwaLan = "192.168.2.1";
  gwbLan = "192.168.3.2";
  ipNodeA = "192.168.2.4";
  ipNodeB = "192.168.3.5";
  dhtPort = 6881;
  libp2pPort = 4001;
  natGateway = lanCidr: iface: {
    virtualisation.vlans = [ 1 ] ++ (if lanCidr == "192.168.2.0/24" then [ 2 ] else [ 3 ]);
    boot.kernel.sysctl."net.ipv4.ip_forward" = true;
    networking.firewall.enable = false;
    environment.systemPackages = [ pkgs.iptables ];
    systemd.services.nat-masquerade = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s ${lanCidr} -o ${iface} -j MASQUERADE";
      };
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "nix-p2p-mainline-rendezvous-vm";

  nodes = {
    gwa = { ... }: natGateway "192.168.2.0/24" "eth1";
    gwb = { ... }: natGateway "192.168.3.0/24" "eth1";

    # The public-segment LOCAL Mainline DHT node (hermetic entry point; never the real swarm).
    mainline = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      environment.systemPackages = [ rendezvousSpike ];
    };

    nodea = { ... }: {
      virtualisation.vlans = [ 2 ];
      networking.defaultGateway = gwaLan;
      networking.firewall.enable = false;
      environment.systemPackages = [ rendezvousSpike ];
    };

    nodeb = { ... }: {
      virtualisation.vlans = [ 3 ];
      networking.defaultGateway = gwbLan;
      networking.firewall.enable = false;
      environment.systemPackages = [ rendezvousSpike pkgs.netcat-openbsd ];
    };
  };

  testScript = ''
    start_all()
    for m in (gwa, gwb, mainline, nodea, nodeb):
        m.wait_for_unit("multi-user.target")

    # NAT is up on both gateways.
    gwa.wait_for_unit("nat-masquerade.service")
    gwb.wait_for_unit("nat-masquerade.service")

    # 1) The local Mainline DHT SERVER comes up on the public segment.
    mainline.execute(
        "${spike} local-bootstrap --bind ${ipMainline} --port ${toString dhtPort} "
        "--hold-secs 120 >/tmp/mainline.log 2>&1 &"
    )
    mainline.wait_until_succeeds("grep -q READY=1 /tmp/mainline.log", timeout=30)

    # 2) Node A boots FIRST and announces its membership (its libp2p port) under the
    #    well-known infohash. Its announce is MASQUERADE'd, so the server records A at gwa's
    #    PUBLIC NAT IP (${ipGwaPublic}), not A's private ${ipNodeA}.
    nodea.execute(
        "${spike} announce --bootstrap ${ipMainline}:${toString dhtPort} "
        "--bind ${ipNodeA} --port ${toString dhtPort} --libp2p-port ${toString libp2pPort} "
        "--hold-secs 90 --reannounce-secs 2 >/tmp/announce.log 2>&1 &"
    )
    nodea.wait_until_succeeds("grep -q ANNOUNCE_OK /tmp/announce.log", timeout=40)

    # 3) Node B boots ~10s LATER and get_peers the infohash — discovering A via BEP5 despite
    #    the NAT and despite never being given A's address.
    nodeb.succeed("sleep 10")
    nodeb.succeed(
        "${spike} discover --bootstrap ${ipMainline}:${toString dhtPort} "
        "--bind ${ipNodeB} --port ${toString dhtPort} --deadline-ms 15000 "
        ">/tmp/discover.log 2>&1"
    )
    discover = nodeb.succeed("cat /tmp/discover.log")
    print(discover)

    # AC#3: B (the late joiner) DISCOVERED A via BEP5 (get_peers) across the NAT.
    assert "DISCOVER_OK" in discover, f"B must discover A via BEP5; got: {discover}"
    # AC#13 (the finding), shown with REAL NAT: the recovered address is gwa's PUBLIC NAT IP
    # (${ipGwaPublic}) — A's private ${ipNodeA} never appears — and carries NO PeerId
    # (peerid=none). B learned A EXISTS; the address is undialable and has nothing to build a
    # /p2p-circuit from. Discovery of membership: YES. Reachability of a NAT'd A: NO.
    assert "peerid=none" in discover, "BEP5 carries no PeerId — the reachability gap (AC#13)"
    assert "${ipGwaPublic}:${toString libp2pPort}" in discover, (
        "the recovered address must be gwa's PUBLIC NAT IP (the announce was MASQUERADE'd), "
        f"proving BEP5 recorded the undialable NAT address, not A's private IP: {discover}"
    )
    assert "${ipNodeA}" not in discover, (
        "A's PRIVATE address must NOT be recoverable — BEP5 only ever saw the NAT source IP"
    )

    # Corroborate "cannot connect directly": nodeb cannot even route to A's private subnet,
    # and the NAT public address:port has no inbound mapping for A's libp2p port.
    nodeb.fail("timeout 3 nc -z ${ipNodeA} ${toString libp2pPort}")
    nodeb.fail("timeout 3 nc -z ${ipGwaPublic} ${toString libp2pPort}")
  '';
}
