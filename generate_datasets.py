"""
generate_datasets.py
====================
DLP Detection Engineering Project — Synthetic Dataset Generator

Generates two datasets used for testing the Splunk-based detection framework:

  1. synthetic_dataset/  — ~24,000 events mixing benign and embedded exfiltration
                           records. Used for detection rule development and unit testing.

  2. benign_dataset/     — ~6,000 events containing only benign traffic.
                           Used exclusively for false-positive rate measurement.

Each dataset contains four CSV files corresponding to the four Splunk log sources:
  - proxy_logs.csv       (network / web proxy traffic)
  - dns_logs.csv         (DNS query logs)
  - email_logs.csv       (email audit logs)
  - dlp_policy_logs.csv  (DLP policy violation events)

Usage:
    python generate_datasets.py

Requirements:
    Python 3.6+  — standard library only (csv, random, datetime, string, base64, os)
    No third-party packages required.

Reproducibility:
    random.seed(42) is set at startup. Running this script with the same Python
    version always produces byte-identical output files.


"""

import csv
import random
import datetime
import string
import base64
import os

# ── Fixed seed — guarantees full reproducibility ──────────────────────────────
random.seed(42)

# ── Output directories ────────────────────────────────────────────────────────
SYNTHETIC_DIR = "synthetic_dataset"
BENIGN_DIR    = "benign_dataset"

os.makedirs(SYNTHETIC_DIR, exist_ok=True)
os.makedirs(BENIGN_DIR,    exist_ok=True)

# ── Shared reference data ─────────────────────────────────────────────────────

# Internal hosts drawn from the asset_inventory.csv lookup table.
# Each entry is (ip_address, username).
INTERNAL_HOSTS = [
    ("10.0.0.5",  "alice"),
    ("10.0.0.6",  "bob"),
    ("10.0.0.8",  "carol"),
    ("10.0.0.9",  "dave"),
    ("10.0.0.10", "eve"),
    ("10.0.0.12", "grace"),
    ("10.0.0.13", "henry"),
    ("10.0.0.14", "ivan"),
    ("10.0.0.19", "mallory"),
    ("10.0.0.22", "oscar"),
    ("10.0.0.31", "pat"),
]

# Benign external domains — real enterprise-relevant destinations.
# These represent normal browsing, SaaS, and cloud platform access.
BENIGN_DOMAINS = [
    "microsoft.com", "office365.com", "teams.microsoft.com", "sharepoint.com",
    "google.com", "youtube.com", "linkedin.com", "github.com",
    "stackoverflow.com", "aws.amazon.com", "zoom.us", "slack.com",
    "salesforce.com", "zendesk.com", "cloudflare.com", "akamai.com",
    "fastly.net", "netflix.com", "spotify.com",
]

# Unsanctioned domains — all present in lookups/unsanctioned_domains.csv.
# Exfiltration proxy records are directed to these destinations.
UNSANCTIONED_DOMAINS = [
    "dropbox.com", "mega.nz", "wetransfer.com", "transfer.sh", "anonfiles.com",
]

# Benign DNS domains — real enterprise name resolution targets.
BENIGN_DNS_DOMAINS = [
    "microsoft.com", "office365.com", "github.com", "linkedin.com",
    "cloudflare.com", "teams.microsoft.com", "slack.com", "zoom.us",
    "google.com", "apple.com",
]

# External email domains used in benign email traffic.
EXTERNAL_EMAIL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com",
    "partner-corp.com", "vendor.io", "client-abc.com",
]

# DLP policy names used in policy log generation.
DLP_POLICIES = [
    "Sensitive-File-Upload", "Bulk-Email-External",
    "Large-Attachment", "Mass-Download",
]

# Simulation base date — all timestamps are offsets from this point.
BASE_TIME = datetime.datetime(2026, 4, 2, 8, 0, 0)


# ── Helper functions ──────────────────────────────────────────────────────────

def rand_time(max_seconds=28800):
    """Return a random timestamp within max_seconds of BASE_TIME (default 8 hr window)."""
    return BASE_TIME + datetime.timedelta(seconds=random.randint(0, max_seconds))


def fmt(dt):
    """Format a datetime as an ISO-style string for CSV output."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def rand_external_ip(prefix="203"):
    """Generate a plausible public IP address."""
    return f"{prefix}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def write_csv(path, headers, rows):
    """Write headers + rows to a CSV file, shuffling rows for realism."""
    random.shuffle(rows)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"  Wrote {len(rows):,} rows  →  {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — PROXY / NETWORK LOGS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Schema: timestamp, src_ip, dest_ip, domain, bytes, user
#
# Benign records:
#   - Random host-domain pairs from the asset inventory and benign domain list.
#   - Transfer sizes drawn from Uniform[1 KB, 2 MB] — typical web browsing range.
#   - Destination IPs are plausible public addresses.
#
# Exfiltration records (UC1 + UC2):
#   - Four specific hosts each upload to one unsanctioned domain.
#   - Total byte volumes exceed the 500 MB detection threshold.
#   - Distributed across 2–6 events per actor to simulate chunked uploads.
#   - All destination domains appear in lookups/unsanctioned_domains.csv.
#
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[1/4] Generating proxy / network logs ...")

proxy_rows = []

# ── Benign proxy traffic ──
for _ in range(9500):
    ip, user = random.choice(INTERNAL_HOSTS)
    domain   = random.choice(BENIGN_DOMAINS)
    t        = rand_time()
    bytes_   = random.randint(1_000, 2_000_000)       # 1 KB – 2 MB
    dest_ip  = rand_external_ip("203")
    proxy_rows.append([fmt(t), ip, dest_ip, domain, bytes_, user])

# ── Exfiltration proxy records (UC1 and UC2 shared events) ──
# Each tuple: (src_ip, user, unsanctioned_domain, total_bytes, num_events)
EXFIL_CASES = [
    ("10.0.0.12", "grace",   "dropbox.com",   350_000_000, 6),   # 350 MB → Dropbox
    ("10.0.0.22", "oscar",   "wetransfer.com",230_000_000, 3),   # 230 MB → WeTransfer
    ("10.0.0.19", "mallory", "mega.nz",        195_000_000, 4),  # 195 MB → MEGA
    ("10.0.0.14", "ivan",    "transfer.sh",    150_000_000, 2),  # 150 MB → transfer.sh
]

for ip, user, domain, total_bytes, n_events in EXFIL_CASES:
    per_event = total_bytes // n_events
    for _ in range(n_events):
        t       = rand_time(3600)                       # compressed into 1-hour window
        dest_ip = rand_external_ip("185")               # separate IP range flags as unusual
        jitter  = random.randint(-1_000, 1_000)
        proxy_rows.append([fmt(t), ip, dest_ip, domain, per_event + jitter, user])

write_csv(
    os.path.join(SYNTHETIC_DIR, "proxy_logs.csv"),
    ["timestamp", "src_ip", "dest_ip", "domain", "bytes", "user"],
    proxy_rows,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — DNS QUERY LOGS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Schema: timestamp, src_ip, query_name, query_type, response
#
# Three population types:
#
#   A) Normal DNS traffic (5,500 records)
#      Structured subdomains (www, api, cdn, login, assets, static, mail)
#      prepended to benign enterprise domains.
#      Subdomain length: 3–25 chars.  Shannon entropy: ~2.0–2.5 bits/char.
#
#   B) Monitoring agent traffic — 10.0.0.7 (412 records)
#      This host is documented in asset_inventory.csv as a legitimate
#      network monitoring tool that generates high DNS query volume.
#      Hostnames follow a structured "probe-XXXXXX-hq" pattern.
#      Subdomain length: ~18–22 chars.  Entropy: ~2.87 bits/char.
#      THIS IS THE FALSE POSITIVE SOURCE for UC3 before entropy tuning.
#      With only query count + length signals, this host would be flagged.
#      The entropy condition (threshold 3.5) correctly clears it.
#
#   C) DNS tunneling hosts (UC3 exfiltration)
#      10.0.0.14 → tunnel-exfil.xyz  (1,842 queries)
#      10.0.0.31 → data-out.io       (987 queries)
#      Subdomains are base64-encoded byte sequences — essentially random.
#      Subdomain length: 55–80 chars.  Shannon entropy: ~4.08–4.21 bits/char.
#      Both hosts exceed ALL THREE thresholds: count > 300, len > 40, entropy > 3.5.
#
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[2/4] Generating DNS query logs ...")

dns_rows = []

# ── A) Normal benign DNS traffic ──
BENIGN_SUBDOMAINS = ["www", "mail", "cdn", "api", "static", "assets", "login"]

for _ in range(5500):
    ip, user = random.choice(INTERNAL_HOSTS)
    domain   = random.choice(BENIGN_DNS_DOMAINS)
    subdomain = random.choice(BENIGN_SUBDOMAINS)
    query    = f"{subdomain}.{domain}"
    t        = rand_time()
    response = rand_external_ip("203")
    dns_rows.append([fmt(t), ip, query, "A", response])

# ── B) Monitoring agent — legitimate high-volume DNS (TL-03 false positive source) ──
# Pattern: "probe-XXXXXX-hq" — structured but longer than typical subdomains.
# This was the host that triggered a false positive before entropy was added.
for _ in range(412):
    t   = rand_time(3600)
    sub = f"probe-{''.join(random.choices(string.ascii_lowercase, k=6))}-hq"
    query = f"{sub}.monitor.internal"
    dns_rows.append([fmt(t), "10.0.0.7", query, "A", "10.0.0.1"])

# ── C) DNS tunneling — exfiltration via encoded subdomains ──
# Mechanism: stolen data is base64-encoded and used as the subdomain of a
# query directed at an attacker-controlled authoritative DNS server.
# The server receives and decodes the queries to reconstruct the stolen data.
# This produces subdomains with near-random character distributions — high entropy.
TUNNEL_HOSTS = [
    ("10.0.0.14", 1842, "tunnel-exfil.xyz"),   # ivan's workstation
    ("10.0.0.31",  987, "data-out.io"),         # pat's admin workstation
]

for ip, count, apex in TUNNEL_HOSTS:
    for _ in range(count):
        # Simulate base64-encoded payload data in the subdomain.
        # A random byte string is encoded; the result has high Shannon entropy.
        payload_bytes = random.randint(30, 60)
        payload       = base64.b64encode(
            ('A' * payload_bytes).encode()      # placeholder for real stolen data
        ).decode().rstrip("=")

        # Truncate to realistic DNS subdomain length (55–80 characters).
        # Real DNS tunneling tools split payloads across multiple queries.
        sub   = payload[:random.randint(55, 80)]
        query = f"{sub}.{apex}"

        t = rand_time(3600)
        # Response is NXDOMAIN — the domain doesn't need to resolve;
        # the attacker's server captures the query itself.
        dns_rows.append([fmt(t), ip, query, "TXT", "NXDOMAIN"])

write_csv(
    os.path.join(SYNTHETIC_DIR, "dns_logs.csv"),
    ["timestamp", "src_ip", "query_name", "query_type", "response"],
    dns_rows,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — EMAIL AUDIT LOGS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Schema: timestamp, user, recipient, action, subject, attachment_size
#
# Four population types:
#
#   A) Normal email traffic (3,900 records)
#      Employees emailing recognizable external business contacts.
#      75% of records have no attachment; 25% have small attachments (50 KB–2 MB).
#
#   B) UC4-A exfiltration: bob — mass external forwarding (147 records)
#      147 emails forwarded to personal gmail and unknown external addresses.
#      Exceeds email_send_threshold (50) AND email_recipient_threshold (30).
#      Represents an employee exfiltrating data before resignation.
#
#   C) UC4-B exfiltration: carol — bulk attachment volume (23 records)
#      23 emails to personal addresses with large attachments (5–20 MB each).
#      Total attachment volume ≈ 312 MB — exceeds email_attach_bytes_threshold (100 MB).
#
#   D) UC4-A exfiltration: dave — mass external sending (61 records)
#      61 emails to competitor domain addresses.
#      Exceeds email_send_threshold (50).
#
#   E) FP case: frank — legitimate bulk email campaign (benign dataset, 62 records)
#      This is the FALSE POSITIVE source for UC4 before tuning.
#      Frank is a sales/marketing employee running a legitimate outreach campaign.
#      Initial threshold of 20 flagged frank. After tuning (TL-01: threshold raised
#      to 50, TL-02: frank added to authorized_senders.csv), no alert fires.
#      NOTE: frank's records appear in the BENIGN dataset, not here.
#
#   F) Control case: eve — normal email, well below threshold (8 records)
#      Confirms the rule produces no alert for low-volume users.
#
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[3/4] Generating email audit logs ...")

email_rows = []

# ── A) Normal benign email traffic ──
for _ in range(3900):
    _, user  = random.choice(INTERNAL_HOSTS)
    ext_dom  = random.choice(EXTERNAL_EMAIL_DOMAINS)
    recipient = f"contact{random.randint(1,99)}@{ext_dom}"
    t         = rand_time()
    # 75% chance of no attachment; 25% small attachment
    attach    = 0 if random.random() < 0.75 else random.randint(50_000, 2_000_000)
    subject   = f"Re: Project Update {random.randint(1,20)}"
    email_rows.append([fmt(t), user, recipient, "send", subject, attach])

# ── B) bob: mass forwarding — UC4 Rule A ──
for i in range(147):
    t = rand_time()
    # First 30 to personal gmail, rest to suspicious external addresses
    if i < 30:
        recipient = f"bob.personal+{i}@gmail.com"
    else:
        recipient = f"ext-contact{i}@outsider.com"
    email_rows.append([fmt(t), "bob", recipient, "forward",
                       "Fwd: Q1 Financials", random.randint(200_000, 800_000)])

# ── C) carol: bulk attachment send — UC4 Rule B ──
# 23 emails × avg 13.5 MB ≈ 312 MB total outbound attachment volume
for i in range(23):
    t = rand_time()
    email_rows.append([fmt(t), "carol", f"personal{i}@gmail.com", "send",
                       f"Files {i}", random.randint(5_000_000, 20_000_000)])

# ── D) dave: mass external sending — UC4 Rule A ──
for i in range(61):
    t = rand_time()
    email_rows.append([fmt(t), "dave", f"ext{i}@competitor.com", "send",
                       "HR data export", random.randint(100_000, 500_000)])

# ── F) eve: control — well below threshold ──
for i in range(8):
    t = rand_time()
    email_rows.append([fmt(t), "eve", f"client{i}@legalcorp.com", "send",
                       f"Contract review {i}", random.randint(50_000, 500_000)])

write_csv(
    os.path.join(SYNTHETIC_DIR, "email_logs.csv"),
    ["timestamp", "user", "recipient", "action", "subject", "attachment_size"],
    email_rows,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DLP POLICY LOGS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Schema: timestamp, user, src_ip, policy_name, action, severity
#
# DLP policy logs serve as enrichment data in all four playbooks.
# They are NOT used as primary detection signals — no exfiltration events
# are embedded here. All records are low-severity "monitor" actions
# representing the kind of background DLP noise any enterprise generates.
#
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[4/4] Generating DLP policy logs ...")

dlp_rows = []

for _ in range(2000):
    ip, user = random.choice(INTERNAL_HOSTS)
    t        = rand_time()
    policy   = random.choice(DLP_POLICIES)
    action   = random.choice(["monitor", "alert", "block"])
    severity = random.choice(["Low", "Medium", "High"])
    dlp_rows.append([fmt(t), user, ip, policy, action, severity])

write_csv(
    os.path.join(SYNTHETIC_DIR, "dlp_policy_logs.csv"),
    ["timestamp", "user", "src_ip", "policy_name", "action", "severity"],
    dlp_rows,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — BENIGN DATASET
# ═══════════════════════════════════════════════════════════════════════════════
#
# The benign dataset contains ZERO embedded exfiltration events.
# Its sole purpose is false-positive rate measurement:
#   - Run all four detection rules against this dataset.
#   - Any alert generated is by definition a false positive.
#
# It contains four files mirroring the synthetic dataset structure.
#
# Special inclusion: frank's bulk email campaign (62 records in benign_email_logs).
# Frank is a sales/marketing employee — his emails are entirely legitimate.
# He was the source of the UC4 false positive resolved in TL-01 and TL-02.
# His records live in the BENIGN dataset to demonstrate that the exception
# mechanism (authorized_senders.csv) correctly suppresses his alert.
#
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[5/5] Generating benign validation dataset ...")

# ── Benign proxy ──
benign_proxy = []
for _ in range(2500):
    ip, user = random.choice(INTERNAL_HOSTS)
    domain   = random.choice(BENIGN_DOMAINS)
    t        = rand_time()
    # Max transfer capped at 50 MB — well below 500 MB detection threshold
    bytes_   = random.randint(500, 50_000_000)
    dest_ip  = rand_external_ip("13")
    benign_proxy.append([fmt(t), ip, dest_ip, domain, bytes_, user])

write_csv(
    os.path.join(BENIGN_DIR, "benign_proxy_logs.csv"),
    ["timestamp", "src_ip", "dest_ip", "domain", "bytes", "user"],
    benign_proxy,
)

# ── Benign DNS ──
benign_dns = []
for _ in range(2000):
    ip, user  = random.choice(INTERNAL_HOSTS)
    domain    = random.choice(BENIGN_DNS_DOMAINS)
    subdomain = random.choice(BENIGN_SUBDOMAINS)
    t         = rand_time()
    response  = rand_external_ip("52")
    benign_dns.append([fmt(t), ip, f"{subdomain}.{domain}", "A", response])

write_csv(
    os.path.join(BENIGN_DIR, "benign_dns_logs.csv"),
    ["timestamp", "src_ip", "query_name", "query_type", "response"],
    benign_dns,
)

# ── Benign email (including frank's FP campaign) ──
benign_email = []

# Normal benign email
for _ in range(1000):
    _, user   = random.choice(INTERNAL_HOSTS)
    ext_dom   = random.choice(EXTERNAL_EMAIL_DOMAINS)
    recipient = f"colleague{random.randint(1,50)}@{ext_dom}"
    t         = rand_time()
    attach    = 0 if random.random() < 0.75 else random.randint(10_000, 500_000)
    benign_email.append([fmt(t), user, recipient, "send",
                         f"Project update {random.randint(1,30)}", attach])

# Frank's legitimate bulk campaign — the TL-01/TL-02 false positive case.
# 62 emails to prospects — legitimate sales outreach, not exfiltration.
# Initial threshold of 20: would trigger a false alarm.
# Tuned threshold of 50: still triggers (62 > 50) until authorized_senders.csv added.
# After TL-02 (frank listed in authorized_senders.csv): no alert fires.
for i in range(62):
    t = rand_time()
    benign_email.append([fmt(t), "frank", f"prospect{i}@lead.com", "send",
                         "Q2 Product Newsletter", random.randint(50_000, 200_000)])

write_csv(
    os.path.join(BENIGN_DIR, "benign_email_logs.csv"),
    ["timestamp", "user", "recipient", "action", "subject", "attachment_size"],
    benign_email,
)

# ── Benign DLP ──
benign_dlp = []
for _ in range(500):
    ip, user = random.choice(INTERNAL_HOSTS)
    t        = rand_time()
    policy   = random.choice(DLP_POLICIES)
    benign_dlp.append([fmt(t), user, ip, policy, "monitor", "Low"])

write_csv(
    os.path.join(BENIGN_DIR, "benign_dlp_logs.csv"),
    ["timestamp", "user", "src_ip", "policy_name", "action", "severity"],
    benign_dlp,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "="*60)
print("Dataset generation complete.")
print("="*60)
print(f"\nSynthetic dataset  ({SYNTHETIC_DIR}/):")
print(f"  proxy_logs.csv       ~{len(proxy_rows):,} records")
print(f"  dns_logs.csv         ~{len(dns_rows):,} records")
print(f"  email_logs.csv       ~{len(email_rows):,} records")
print(f"  dlp_policy_logs.csv   {len(dlp_rows):,} records")
total_syn = len(proxy_rows) + len(dns_rows) + len(email_rows) + len(dlp_rows)
print(f"  TOTAL:               ~{total_syn:,} records")
print(f"\nBenign dataset     ({BENIGN_DIR}/):")
print(f"  benign_proxy_logs.csv  {len(benign_proxy):,} records")
print(f"  benign_dns_logs.csv    {len(benign_dns):,} records")
print(f"  benign_email_logs.csv  {len(benign_email):,} records")
print(f"  benign_dlp_logs.csv    {len(benign_dlp):,} records")
total_ben = len(benign_proxy)+len(benign_dns)+len(benign_email)+len(benign_dlp)
print(f"  TOTAL:                 {total_ben:,} records")
print(f"\nGrand total:  {total_syn + total_ben:,} records across 8 files")
print(f"Random seed:  42  (fully reproducible)")
