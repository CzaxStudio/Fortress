# ⬡ Fortress

**Network Recon · OSINT · Intelligence DSL**

Fortress (`.frt`) is a domain-specific language built for network reconnaissance, OSINT investigations, and security research. It combines Python-style readability with C#-style structure, and has first-class support for DNS, geolocation, port scanning, WHOIS, TLS inspection, banner grabbing, and more — all with clean, expressive syntax.

---

## Installation

### One-line install (Linux / macOS)

No Go required. The installer downloads the correct pre-built binary for your platform.

```bash
curl -fsSL https://fortress-lang.dev/install.sh | bash
```

Or manually:
```bash
chmod +x install.sh && ./install.sh
```

### Windows

Download the latest `fortress-windows-amd64.exe` from the
[Releases page](https://github.com/fortress-lang/fortress/releases),
rename it to `fortress.exe`, and add its folder to your `PATH`.

### Build from source (maintainers / contributors)

```bash
# Requires Go 1.21+ — only needed if you're building the interpreter itself
git clone https://github.com/fortress-lang/fortress
cd fortress
go build -o fortress .

# Cross-compile all platform binaries for a release
chmod +x build-release.sh && ./build-release.sh
# → produces dist/fortress-linux-amd64, fortress-darwin-arm64, fortress-windows-amd64.exe, …
```

---

## CLI Commands

```bash
fortress run script.frt              Execute a .frt script
fortress build myapp.exe script.frt  Compile script into a self-contained executable
fortress build myapp.exe *           Bundle ALL .frt files in the current directory
fortress create script.frt           Create new script from template
fortress --version                   Show version and build info
fortress --help                      Full language reference
fortress install-icon                Register .frt file association + icon (Windows)
```

### Building self-contained executables

The `build` command produces a **standalone executable** that embeds your `.frt`
source inside the Fortress interpreter. The output file runs on any machine —
no Fortress installation, no Go, no dependencies needed.

```bash
# Single script → one exe
fortress build scanner.exe scanner.frt

# Entire project → one exe  (entry point = main.frt, or first .frt alphabetically)
fortress build myapp.exe *
```

**How it works:** The built executable is a copy of the Fortress binary with
your script(s) appended in a compressed payload. On startup it detects the
embedded source and runs it automatically.

**Cross-platform note:** `fortress build` always produces a binary for the
*current* platform. To ship a Windows exe from Linux, run the build step on
Windows (or use a CI matrix).

---


## Package Manager

Fortress has a built-in package manager for installing and publishing `.frt` libraries.

### Install a library

```bash
fortress get site=<library-name>            # Install from registry
fortress get site=<library-name>@1.2.0     # Install specific version
fortress get file=mylib-1.0.0.frtpkg       # Install from local file
```

### Manage libraries

```bash
fortress list                               # Show all installed libraries
fortress info site=<library-name>          # Show library details and exports
fortress remove site=<library-name>        # Uninstall a library
```

### Publish a library

```bash
fortress myscript.frt create lib site=mylib          # Publish one file
fortress * create lib site=mylib                     # Publish all .frt files in directory
```

The interactive wizard will prompt for: display name, version, author, description, license, tags, homepage, and repository. After publishing, a `.frtpkg` archive is created that you can share or upload to GitHub.

### Use a library in scripts

```
import mylib
import mylib as ml

mylib.myProbe("target.com")
ml.myProbe("target.com")       // same thing with alias
```

Libraries are installed to:
- **Windows:** `%APPDATA%\Fortress\libs\`
- **Linux:** `~/.fortress/libs/`
- **macOS:** `~/Library/Fortress/libs/`

## Language Reference

### Variables
No type declarations — types are inferred automatically (like Python):

```fortress
let target  = "192.168.1.1"
let ports   = [80, 443, 8080]
let timeout = 0.5
let active  = true
let data    = { "key": "value", "count": 42 }
```

### Output — `compute()`
```fortress
compute("Hello, Fortress!")
compute("IP: " -> geo.city -> ", " -> geo.country)
compute(result.open_count, "ports open")
```

### Input — `capture()`
```fortress
capture("Enter target IP: ") -> ip
capture("Port (default 80): ") -> port
```

### Concatenation — `->`
The `->` operator concatenates any values as strings:
```fortress
let msg = "Found " -> count -> " open ports on " -> host
```

### Functions — `probe`
```fortress
probe greet(name) {
    return "Hello, " -> name -> "!"
}

probe fullRecon(ip, timeout) {
    let geo = geolocate(ip)
    let scan = portscan(ip)
    return { "geo": geo, "scan": scan }
}
```

### Conditionals
```fortress
if status == "online" {
    compute("Host is up")
} elif status == "slow" {
    compute("High latency detected")
} else {
    compute("Host unreachable")
}
```

### Loops

**C-style `scan` loop:**
```fortress
scan (let i = 0; i < 10; i++) {
    compute("Port: " -> str(i + 8080))
}
```

**For-each `each` loop:**
```fortress
each ip in results.ips {
    compute("  Found: " -> ip)
}
```

**While loop with `until`:**
```fortress
let attempts = 0
until attempts < 3 {
    let result = portscan(target)
    if result.open_count > 0 { break }
    attempts++
}
```

---

## Network & OSINT Builtins

### `resolve(host)` — DNS Enumeration
```fortress
let dns = resolve("example.com")
// dns.ips     → list of IPs
// dns.mx      → mail server records
// dns.ns      → nameservers
// dns.txt     → TXT records
// dns.cname   → canonical name
```

### `geolocate(ip)` — IP Geolocation
Accurate to city level (~25km radius). Uses ip-api.com.
```fortress
let geo = geolocate("8.8.8.8")
// geo.city, geo.regionName, geo.country, geo.countryCode
// geo.lat, geo.lon, geo.timezone
// geo.isp, geo.org, geo.as, geo.asname
// geo.proxy, geo.hosting, geo.mobile
```

### `whois(target)` — WHOIS Lookup
```fortress
let w = whois("google.com")
// w.registrar, w.created, w.expires, w.updated
// w.name_servers, w.status, w.organization, w.country
// w.raw  → full raw WHOIS response
```

### `portscan(host, ports?, timeout_sec?)` — TCP Port Scanner
```fortress
let scan = portscan("example.com")
let scan = portscan("10.0.0.1", [22, 80, 443, 3389], 0.5)
// scan.open        → list of { port, service, banner }
// scan.open_count  → number of open ports
// scan.scanned     → total ports scanned
```

### `certinfo(host, port?)` — TLS Certificate Inspector
```fortress
let cert = certinfo("github.com")
// cert.subject, cert.issuer, cert.issuer_org
// cert.not_before, cert.not_after, cert.days_left
// cert.expired, cert.sans, cert.sig_algo, cert.serial
```

### `banner(host, port)` — Banner Grabbing
```fortress
let b = banner("target.com", "22")
// b.banner   → raw service banner
// b.service  → guessed service name
```

### `headers(url)` — HTTP Header Analysis
```fortress
let h = headers("https://example.com")
// h.status, h.headers (map), h.server, h.powered_by
// h.security_score  → 0-6 security header score
// h.security_issues → list of missing security headers
```

### `crawl(url)` — Web Metadata Extraction
```fortress
let page = crawl("https://example.com")
// page.title, page.description, page.keywords
// page.technologies  → detected tech stack
// page.link_count, page.image_count, page.form_count
```

### `revdns(ip)` — Reverse DNS
```fortress
let r = revdns("8.8.8.8")
// r.primary    → primary hostname
// r.hostnames  → all PTR records
```

### `subnet(cidr)` — Subnet Calculator
```fortress
let s = subnet("192.168.1.0/24")
// s.network, s.broadcast, s.first_host, s.last_host
// s.subnet_mask, s.prefix, s.total_hosts, s.usable_hosts
```

### `asnlookup(ip_or_asn)` — ASN/BGP Info
```fortress
let asn = asnlookup("8.8.8.8")
let asn = asnlookup("AS15169")
```

### `emailval(email)` — Email Validation
```fortress
let e = emailval("user@example.com")
// e.valid, e.mx_valid, e.deliverable, e.disposable
// e.primary_mx, e.mx_records
```

### `phoninfo(number)` — Phone Number Analysis
```fortress
let p = phoninfo("+14155552671")
// p.e164, p.country, p.country_code, p.line_type, p.valid
```

### `macvendor(mac)` — MAC Vendor Lookup
```fortress
let m = macvendor("00:1A:2B:3C:4D:5E")
// m.vendor, m.oui, m.formatted
```

### `iprange(cidr_or_range, max?)` — IP Range Expansion
```fortress
let ips = iprange("10.0.0.0/28")
let ips = iprange("192.168.1.1-192.168.1.50", 100)
// ips.ips    → list of IP strings
// ips.count  → number of IPs
```

### `trace(host)` — Path Tracing
```fortress
let t = trace("8.8.8.8")
// t.hops  → list of { ttl, hop, rtt, reached }
```

---

## Reporting

### `report` — Formatted Output
```fortress
report "Investigation Report" as "text" {
    target: ip,
    location: geo.city -> ", " -> geo.country,
    open_ports: scan.open_count,
    scanned_at: now()
}
```
Formats: `"text"` (default, box-drawn table), `"json"`, `"html"`

### `save` — Write to File
```fortress
let output = jsondump(result)
save output to "report.json"
```

---

## Standard Library

| Function | Description |
|---|---|
| `len(x)` | Length of string/list/map |
| `str(x)` | Convert to string |
| `int(x)` | Convert to integer |
| `float(x)` | Convert to float |
| `append(list, val)` | Add to list (mutates) |
| `contains(x, val)` | Check membership |
| `split(s, sep?)` | Split string |
| `join(list, sep?)` | Join list to string |
| `upper/lower/trim(s)` | String transforms |
| `replace(s, old, new)` | String replace |
| `slice(x, start, end?)` | Slice string or list |
| `range(end)` | Generate integer range |
| `sort(list)` | Sort a list |
| `unique(list)` | Deduplicate list |
| `keys/values(map)` | Map keys/values |
| `haskey(map, key)` | Check map key |
| `merge(map1, map2)` | Merge maps |
| `jsonparse(s)` | Parse JSON string |
| `jsondump(val)` | Serialize to JSON |
| `httpget(url, headers?)` | HTTP GET request |
| `httppost(url, body)` | HTTP POST request |
| `readfile(path)` | Read file contents |
| `env(name)` | Get env variable |
| `sleep(seconds)` | Pause execution |
| `timestamp()` | Unix timestamp |
| `now()` | Formatted datetime |
| `isip(s)` | Check if IPv4 |
| `isipv6(s)` | Check if IPv6 |
| `format(fmt, ...)` | Printf-style format |
| `exit(code?)` | Exit program |

---

## Example Scripts

### Quick IP Recon
```fortress
capture("Target IP: ") -> ip
let geo  = geolocate(ip)
let scan = portscan(ip)
let cert = certinfo(ip)

report "Quick Scan" {
    ip:        ip,
    location:  geo.city -> ", " -> geo.country,
    isp:       geo.isp,
    open:      scan.open_count,
    tls_valid: str(not cert.expired)
}
```

### Batch Domain Scan
```fortress
let targets = ["github.com", "cloudflare.com", "stripe.com"]

each domain in targets {
    let dns  = resolve(domain)
    let cert = certinfo(domain)
    compute(domain -> "  →  " -> dns.ips[0] -> "  TLS: " -> str(cert.days_left) -> "d left")
}
```

### Save JSON Report
```fortress
let ip   = "1.1.1.1"
let geo  = geolocate(ip)
let data = jsondump(geo)
save data to "geo_report.json"
```

---

## Legal Notice

Fortress is designed for **authorized** network reconnaissance, security research, and legal OSINT operations. Do not use against systems you do not own or have explicit permission to test. The authors assume no liability for misuse.

---

*Fortress v1.0.0 — Built in Go · Extension `.frt` · MIT License*
