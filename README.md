# CR-18 / Module 5 / N5b — Intermediate Lateral Movement & Network Pivoting

A KYPO cyber range training scenario (CTF-style) covering multi-tier lateral movement and pivoting across a segmented DMZ / Internal / Management network.

## Overview

This is the follow-up to N5a, set against a network the client has since segmented into three tiers: a DMZ facing the outside, an Internal tier behind it, and a locked-down Management tier. Trainees start with access to an assessment machine in the DMZ and must work their way inward.

The exercise chains several distinct techniques into a single attack path: a leaked credential exposed via an anonymous file share, local privilege escalation through a misconfigured sudo rule, an application-layer tunnelling tool used to pivot across network tiers, and abuse of a trust relationship between a misconfigured file share and a scheduled task to gain a second, unsolicited pivot. The exercise is designed to show that network segmentation alone does not stop an attacker who can chain small misconfigurations together.

## Prerequisites

- Comfort using a Linux shell and an SSH client
- Basic understanding of TCP/IP networking and firewalls
- Familiarity with dictionary/enumeration tooling (e.g. nmap, smbclient)
- Completion of N5a (Beginner Lateral Movement & Network Pivoting), or equivalent hands-on pivoting experience

## Learning Outcomes

- Demonstrate lateral movement across a segmented DMZ, Internal, and Management architecture
- Chain multiple pivoting techniques to bypass layered network defenses
- Exploit implicit trust and shared services (SMB, NFS) in enterprise environments
- Understand how routing, service, and scheduling misconfigurations undermine network segmentation
- Relate multi-tier pivoting attacks to real-world enterprise compromise scenarios

## Scenario Structure

The training is delivered as a sequence of levels:

| # | Title | Type |
|---|-------|------|
| 0 | Introduction | Info |
| 1 | Get Access | Access (console login) |
| 2 | Background — Pivoting, NFS Trust & Scheduled Tasks | Info |
| 3 | Breach the DMZ | Training |
| 4 | Escalate on the DMZ Host | Training |
| 5 | Pivot Into the Internal Network | Training |
| 6 | Abuse a Misconfigured File Share | Training |
| 7 | Reach Management | Training |
| 8 | Module Completed | Info |

Estimated total duration: ~70 minutes.

An in-scenario background level introduces application-layer tunnelling, NFS trust/`no_root_squash`, and scheduled-task abuse before the hands-on levels begin, so trainees have the concepts needed to complete the exercise without prior exposure to these techniques. A companion reference document (referenced in-scenario as a "Tools & Techniques Manual") is also made available to trainees outside the sandbox.

## Topology

The environment is segmented into three network tiers, connected by a router and by dual-homed hosts that bridge between them:

- **Attacker machine** (`vma`) — the trainee's entry point; reachable only on the DMZ tier.
- **DMZ host** (`dmzhost`) — dual-homed across the DMZ and Internal tiers; exposes a file-sharing service and becomes the trainee's first pivot point once compromised.
- **Application server** (`appserver`) — sits on the Internal tier only; not directly reachable from the DMZ.
- **NFS server** (`nfsserver`) — dual-homed across the Internal and Management tiers; hosts a file share that becomes the bridge into the final tier.
- **Management host** (`mgmthost`) — the final target, reachable only from the Management tier.

Only `vma` is directly visible to the trainee at the start; the remaining hosts are discovered and reached progressively as each tier is breached. The design deliberately keeps each tier's hosts unreachable from outside their tier except through the dual-homed bridge hosts, so that reaching the final target requires chaining pivots rather than any single exploit.

## Skills Practiced

- Enumeration and exploitation of an anonymously accessible file share
- Local privilege escalation via sudo misconfiguration
- Application-layer network tunnelling/pivoting across segmented tiers
- Exploiting NFS export trust and root-squashing misconfigurations
- Abusing a scheduled task to gain remote code execution
- Chaining multiple pivots to cross successive network segments

## MITRE ATT&CK Coverage

Techniques referenced across the scenario include:

- Valid Accounts (T1078)
- Network Service Discovery (T1046)
- External Remote Services (T1133)
- Unsecured Credentials (T1552)
- Abuse Elevation Control Mechanism (T1548)
- Proxy (T1090)
- Protocol Tunneling (T1572)
- Trusted Relationship (T1199)
- Exploitation for Privilege Escalation (T1068)
- Scheduled Task/Job (T1053)

## Notes

This repository contains the scenario definition (topology and training content) for deployment on a KYPO-based cyber range. Solutions, hints, and flag values are intentionally excluded from this README.
