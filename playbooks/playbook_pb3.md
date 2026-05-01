# Playbook PB3 — DNS-Based Data Exfiltration

**Detection Rule:** UC3 — DNS-Based Exfiltration (`uc3_dns_exfil.spl`)  
**Version:** 1.0 | **Author:** Detection Engineering Project  
**Severity Levels Covered:** Medium / High / Critical  
**⚠ Note:** DNS tunneling is a high-sophistication technique. Any confirmed alert should be treated as at least High severity and escalated promptly.

---

## Overview

This playbook guides a SOC analyst when UC3 fires an alert for a host exhibiting DNS tunneling indicators: high query volume, long subdomain strings, and high Shannon entropy. DNS tunneling is used to covertly exfiltrate data — or establish command-and-control — by encoding information into DNS queries directed at an attacker-controlled authoritative name server.

**Alert trigger summary:** A source host exceeded the query count threshold (default: 300/hour), average subdomain length threshold (default: 40 chars), and entropy threshold (default: 3.5 bits/char) within a one-hour window.

---

## Step 1 — Initial Validation

**Goal:** Confirm the alert represents genuine tunneling rather than a legitimate high-volume DNS source.

1. **Review the alert fields:** `src_ip`, `hostname`, `query_count`, `avg_subdomain_len`, `avg_entropy`, `sample_queries`, `first_seen`, `last_seen`.

2. **Visually inspect the sample queries** — tunneling subdomains are visually distinct:
   - Tunneling: `aGVsbG8gd29ybGQ.attacker-domain.com` (random-looking base64 string)
   - Legitimate: `prod-monitoring-agent-hq01.telemetry.company.com` (readable, structured)

3. **Check `asset_inventory.csv`** for the source host:
   ```spl
   | inputlookup asset_inventory.csv | search src_ip=<src_ip>
   ```
   - If the asset notes indicate a network monitoring agent or a known high-DNS source, verify the entropy value.
   - Monitoring agents typically show entropy < 3.2; if entropy > 3.5, proceed to Step 2 regardless.

4. **Check the contacted domain against threat intelligence** (if available):
   - Is the authoritative domain newly registered?
   - Does it appear in known DNS tunneling or C2 threat intelligence feeds?

5. **Check if 10.0.0.7 (or similar documented monitoring hosts) pattern matches:**
   - This host is documented in `asset_inventory.csv` as a legitimate high-DNS source.
   - Its average entropy was 2.87 — below the 3.5 threshold.
   - If alert entropy is below 3.2, review whether the threshold needs adjustment for a new monitoring tool.

**Decision point:**
- Source is a documented monitoring agent with entropy < 3.2 → Likely false positive. Update `asset_inventory.csv` notes. Adjust threshold if necessary. Log tuning action.
- Entropy ≥ 3.5 AND long subdomains confirmed → Continue to Step 2 with High/Critical priority.

---

## Step 2 — Enrichment

**Goal:** Gather technical and contextual evidence to support the investigation and forensic response.

1. **Pull all DNS queries from the flagged host in the detection window:**
   ```spl
   index=dns_logs src_ip=<src_ip> earliest=<first_seen> latest=<last_seen>
   | eval subdomain=mvindex(split(query_name,"."),0)
   | eval sub_len=len(subdomain)
   | table _time query_name subdomain sub_len query_type response_ip
   | sort _time
   ```

2. **Identify the apex domain (authoritative server) being queried:**
   ```spl
   index=dns_logs src_ip=<src_ip> earliest=<first_seen> latest=<last_seen>
   | eval apex=mvjoin(mvindex(split(query_name,"."),-2,0),".")
   | stats count by apex
   | sort - count
   ```

3. **Perform WHOIS and DNS lookups on the apex domain:**
   - Registration date (newly registered = high risk)
   - Registrar (privacy-proxy registrars = higher risk)
   - Authoritative name server country / ASN
   - Passive DNS history

4. **Correlate with network flow logs** to confirm outbound traffic pattern:
   ```spl
   index=network_flows src_ip=<src_ip> dest_port=53 earliest=<first_seen>
   | stats sum(bytes_out) as dns_bytes count by dest_ip
   | sort - dns_bytes
   ```

5. **Check for correlated UC1/UC2 alerts** (compound exfiltration scenario):
   ```spl
   index=notable src_ip=<src_ip> earliest=-24h
   | table _time alert_name severity
   ```

6. **Identify the logged-in user** at the time of the alert from authentication logs.

7. **Review the process tree on the endpoint** (if EDR available):
   - What process initiated the DNS queries? (Common: `nslookup`, `iodine`, `dnscat2`, `curl`)
   - Is the process name expected on this host?

---

## Step 3 — Containment and Remediation

**Goal:** Stop the tunneling immediately; prevent further data loss; preserve forensic evidence.

### Immediate actions (execute in parallel where possible):

1. **Block the apex domain at the DNS resolver:**
   - Add the domain to the DNS sinkhole or resolver block list.
   - Verify: query the domain from the flagged host after blocking; it should return NXDOMAIN or sinkhole IP.

2. **Block at the network perimeter (firewall):**
   - Block all outbound UDP/TCP port 53 traffic from `<src_ip>` to destinations other than the corporate DNS resolver.
   - This prevents the attacker from switching to an alternative DNS resolver.

3. **Isolate the host from the network:**
   - DNS tunneling typically indicates active compromise (not just misuse).
   - Request host isolation from the endpoint team immediately for Medium+ severity.
   - Isolation should cut all network access except for the security management channel.

4. **Preserve forensic evidence BEFORE remediation:**
   - Capture a live memory image of the host (memory contains running processes, network connections, and potentially decrypted payload data).
   - Capture a full disk image.
   - Export all DNS logs for the host from the detection window plus 24 hours prior.
   - Preserve the Splunk alert and enrichment query results.
   - **Do not power off the host** until memory capture is complete.

5. **Revoke active sessions** for the associated user account:
   - Invalidate SSO tokens, VPN sessions, and cloud app sessions.

---

## Step 4 — Escalation, Communication, and Documentation

**⚠ DNS tunneling is always a high-severity event. Do not downgrade without explicit CISO approval.**

### Escalation matrix:

| Condition | Escalate To | SLA |
|---|---|---|
| Any confirmed DNS tunnel | CISO + Incident Response team | Immediately |
| Evidence of C2 communication | CISO + IR + Threat Intelligence | Immediately |
| Data exfiltration volume confirmed | CISO + Legal + Compliance | Immediately |
| External attacker (compromised host) | CISO + IR + Legal | Immediately |
| Insider threat suspected | CISO + HR + Legal | Immediately |

### Forensic handoff:

- Transfer memory image, disk image, and log exports to the forensic investigation team.
- Provide the apex domain, query samples, and timeline to the Threat Intelligence team for indicator sharing.
- If external attacker involvement is confirmed, consider reporting to law enforcement and/or ISACs as appropriate.

### Documentation requirements:

- Open a Priority 1 incident ticket immediately upon confirmation.
- Record: alert ID, host, user, apex domain, query count, entropy value, timeline, all actions taken and their timestamps.
- Document all forensic evidence collected and its chain of custody.
- File a post-incident report within 5 business days of closure.
