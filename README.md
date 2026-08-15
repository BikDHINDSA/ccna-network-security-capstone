# CCNA Network Security Capstone

A segmented enterprise network, built and secured in Cisco Packet Tracer, with real
detection telemetry flowing into Microsoft Sentinel and the whole design maintained from a
single config-as-code source. Four phases: build it, secure it, monitor it, make it
maintainable.

This project sits alongside a separate [Azure/Sentinel SOC capstone](https://github.com/BikDHINDSA/sysmon-to-sentinel-detection-pipeline) — that one covers
cloud-native detection engineering; this one covers the network layer underneath it, and
the two share the same Sentinel workspace.

---

## The four phases

1. **[Build](docs/Phase1-Topology.md)** — segmented VLANs, DHCP, port security, a fully
   routed and validated baseline network
2. **[Secure](docs/Phase2-Segmentation.md)** — a perimeter firewall (evolved into a proper
   three-legged design) and least-privilege ACLs between every VLAN
3. **[Detect](docs/Phase3-Detection.md)** — syslog centralized across the network, a
   custom log parser, and real ingestion into Microsoft Sentinel
4. **[Automate](docs/Phase4-Automation.md)** — the whole VLAN/ACL design regenerated from
   one YAML file instead of retyped per device

## Architecture

```
                                   [ISP Cloud / WAN]
                                          |
                                     [ Router0 ]  (edge)
                                          |
                                     [ ASAv0 ]     (firewall — 3 legs: outside/inside/dmz)
                                    /        \
                              [ L3-Core ]   [ WEB-DMZ ]
                          /         |
                     [Access-SW1] [Access-SW2]
                        /  \          /  \
                    MGMT  USERS   MGMT  USERS
```

| VLAN | Name | Subnet | What's in it |
|---|---|---|---|
| 10 | MGMT | 10.10.10.0/24 | Admin/management traffic |
| 20 | USERS | 10.10.20.0/24 | End-user PCs |
| 30 | SERVERS | 10.10.30.0/24 | DNS/DHCP, syslog/AAA |
| — | DMZ | 10.10.40.0/24 | Public web server, on its own firewall interface |
| 99 | NATIVE (unused) | 10.10.99.0/24 | Native VLAN hardening |

## Repo layout

```
docs/                    — one write-up per phase
packet-tracer/            — the .pkt file
automation/               — YAML source, Jinja templates, generated configs
detection/                — syslog parser, raw logs, parsed output
screenshots/               — evidence, one folder per phase
```

## Skills this project actually demonstrates

- VLAN segmentation, inter-VLAN routing, DHCP relay
- Firewall design: NAT, security zones, least-privilege ACLs
- Centralized logging and SIEM ingestion (Sentinel, KQL)
- Config-as-code: Python, Jinja2, YAML

---

## How this actually went

The honest version: this took a lot longer than planned, and most of that time wasn't
spent building — it was spent figuring out why something that should've worked, didn't.
Packet Tracer is a simulator, not real Cisco hardware, and it doesn't always behave like
the documentation says it should. A decent chunk of this project ended up being about
telling the difference between "I configured this wrong" and "this simulator just can't do
that" — and proving which one it was instead of guessing.

A few examples that stood out:

**ACLs applied to VLAN interfaces silently didn't work.** The command went in with no
error, `show running-config` even showed it — but it never actually filtered anything.
Took applying it to the physical ports instead to get real enforcement.

**The firewall's ACL couldn't match traffic against its own NAT'd addresses**, which is
supposed to happen automatically on real ASA hardware. Fixed by writing the ACL against
the translated public IP directly instead of the internal one.

**Locking a VLAN down with least-privilege rules also blocked the syslog and NTP traffic
needed to monitor that same VLAN.** Nobody plans for the security rules to break the
monitoring — but that's exactly what happened, twice, on two different ACLs, until syslog
and NTP got their own explicit permit lines.

**The firewall in this simulator can't do UDP inspection at all**, and has no logging
capability whatsoever — not a bug, just missing from this particular image. That meant
some things (like the edge router's NTP sync through the firewall) were never going to
work, no matter how the config was written. Confirming that took real testing — ICMP
against UDP, checking what commands even existed — not just giving up on the first try.

**A parser bug quietly mislabeled almost every interface event** because the word "down"
happens to be hiding inside the word "UPDOWN." Small thing, but it would've made the whole
detection dataset wrong if it hadn't been caught.

None of that is really a Packet Tracer complaint. If anything, chasing these down was the
most useful part of the project — actual troubleshooting, actual "is this me or is this
the tool," which is a big part of what the job itself looks like.

## Where this could go if I kept going

This was scoped to fit CCNA-level networking plus a realistic amount of security hardening
on top. There's a lot more that could be added if this became an ongoing project instead
of a capstone:

- **Real IDS/IPS** — something like Snort or Suricata watching traffic between segments,
  not just relying on ACL logs
- **Certificate-based device authentication** instead of open trunk/access ports
- **802.1X on the access ports**, so a device has to authenticate before it even gets on
  the network, rather than just landing in whatever VLAN the port is assigned to
- **A real SOAR playbook** off the back of the Sentinel alerts — right now the pipeline
  proves detection is possible; it doesn't yet do anything automatically when something
  fires
- **Vulnerability scanning** against the DMZ host on a schedule, feeding results into the
  same workspace
- **Redundancy** — right now there's a single point of failure at almost every layer
  (one core switch, one firewall); a real deployment would need HA pairs and redundant
  links

None of that was necessary to prove the core ideas here — segmentation, least privilege,
detection, and maintainability — but it's the natural next layer if this were a real
network instead of a lab.

---

## Contact

Bikram Dhindsa
[GitHub](https://github.com/BikDHINDSA) · [LinkedIn](https://linkedin.com/in/dhindsa-bikram)