# My Simples Threat Intelligence Tool

Just a simples tool, to search some IOCs. It's not a product, just a tool that I build to my own activites.

----------------------------------------------------

A command-line tool for **IOC hunting, pivoting and binary triage** during Malware Analysis, Threat Hunting and Incident Response. It unifies three intelligence sources behind a single, consistent command tree so an analyst can enrich, correlate and triage indicators without switching tools.

Sources (for now):

- **ThreatFox** (abuse.ch) - IOC lookup and correlation
- **MalwareBazaar** (abuse.ch) - malware sample metadata and download
- **VirusTotal** - artifact and IP triage (imports, PE sections and entropy, verdicts, threat classification, YARA and Sigma matches)

## Please Install the Requirements

- Python 3.7+
- `requests`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Take your API Keys

- **abuse.ch Auth-Key** (required for `tf-*` and `mb-*` commands): create a free account at <https://auth.abuse.ch/>.
- **VirusTotal API Key** (required for `vt-*` commands): available at <https://www.virustotal.com/>.

The abuse.ch Auth-Key can be passed with `--auth-key` or set as an environment variable (`THREATFOX_AUTH_KEY`, `MALWAREBAZAAR_AUTH_KEY`, or the shared `ABUSECH_AUTH_KEY`). The VirusTotal key is passed with `--vt-api-key`.

```bash
export ABUSECH_AUTH_KEY="your_abusech_key"
```

## Some Usage Examples

```bash
python3 threat_intell_hunting.py <command> [args] [flags]
python3 threat_intell_hunting.py --help
python3 threat_intell_hunting.py <command> --help
```

Common flags available on every command: `--json`, `--iocs-only`, `-o/--output FILE`.

### Some ThreatFox Example

```bash
# Search an IOC (IP / domain / URL); wildcard by default
python3 threat_intell_hunting.py tf-ioc 94.103.84.81 --auth-key <KEY>
python3 threat_intell_hunting.py tf-ioc example.com --exact --auth-key <KEY>

# IOCs associated with a hash
python3 threat_intell_hunting.py tf-hash <md5|sha256> --auth-key <KEY>

# IOCs by malware family / tag
python3 threat_intell_hunting.py tf-malware "Cobalt Strike" --limit 200 --auth-key <KEY>
python3 threat_intell_hunting.py tf-tag Magecart --auth-key <KEY>

# Recent IOCs (last N days, 1-7)
python3 threat_intell_hunting.py tf-recent --days 3 --auth-key <KEY>
```

### Some MalwareBazaar Example

```bash
# Full sample details by hash
python3 threat_intell_hunting.py mb-hash <sha256|sha1|md5> --auth-key <KEY>

# Samples by tag / signature / imphash / YARA rule
python3 threat_intell_hunting.py mb-tag TrickBot --auth-key <KEY>
python3 threat_intell_hunting.py mb-sig TrickBot --auth-key <KEY>
python3 threat_intell_hunting.py mb-imphash <imphash> --auth-key <KEY>
python3 threat_intell_hunting.py mb-yara win_remcos_g0 --auth-key <KEY>

# Recent detections (last N hours, 1-168)
python3 threat_intell_hunting.py mb-recent --hours 48 --auth-key <KEY>

# Download the sample (ZIP, password: infected)
python3 threat_intell_hunting.py mb-download <sha256> -o sample.zip --auth-key <KEY>
```

### Some VirusTotal Example

```bash
# Full artifact triage by hash
python3 threat_intell_hunting.py vt-hash <sha256|sha1|md5> --vt-api-key <VT_KEY>

# Pull a specific vendor verdict
python3 threat_intell_hunting.py vt-hash <hash> --vendor "SentinelOne (Static ML)" --vt-api-key <VT_KEY>

# IP reputation triage
python3 threat_intell_hunting.py vt-ip 94.103.84.81 --vt-api-key <VT_KEY>

# Raw JSON / save response / indicator-only
python3 threat_intell_hunting.py vt-hash <hash> --json --vt-api-key <VT_KEY>
python3 threat_intell_hunting.py vt-hash <hash> -o vt.json --vt-api-key <VT_KEY>
python3 threat_intell_hunting.py vt-ip 1.2.3.4 --iocs-only --vt-api-key <VT_KEY>
```

## A List of Commands

| Command | Source | Purpose |
|---|---|---|
| `tf-ioc` | ThreatFox | Search IOC (IP/domain/URL) |
| `tf-hash` | ThreatFox | IOCs associated with a hash |
| `tf-malware` | ThreatFox | IOCs by malware family |
| `tf-tag` | ThreatFox | IOCs by tag |
| `tf-recent` | ThreatFox | Recent IOCs (days) |
| `mb-hash` | MalwareBazaar | Full sample details |
| `mb-tag` | MalwareBazaar | Samples by tag |
| `mb-sig` | MalwareBazaar | Samples by signature |
| `mb-imphash` | MalwareBazaar | Samples by imphash |
| `mb-yara` | MalwareBazaar | Samples by YARA rule |
| `mb-recent` | MalwareBazaar | Recent detections (hours) |
| `mb-download` | MalwareBazaar | Download sample (ZIP, password: infected) |
| `vt-hash` | VirusTotal | Artifact triage (imports/sections/verdict/YARA/Sigma) |
| `vt-ip` | VirusTotal | IP reputation triage |

## Output conventions

- `[!]` highlights investigation-worthy signals (malicious/suspicious counts, high-entropy sections, `rx` section flags, YARA/Sigma hits, threat labels).
- `[+]` and `[-]` are informational.
- `--iocs-only` prints one indicator per line for direct use in hunting pipelines. On `vt-*` commands it prints the queried indicator when the artifact or IP is known to VirusTotal (empty otherwise), acting as a quick known/unknown check.

## Notes

- I use a lot of Bash Scripting, to take the better output. I recommend that!
- Downloaded MalwareBazaar samples are delivered as password-protected ZIP archives (password: `infected`). Handle in an isolated analysis environment.
- API rate limits apply per source and per key tier. VirusTotal returns HTTP 429 when the quota is exceeded.
