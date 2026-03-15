<div align="center">

```
  ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
  █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
  ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

**A purpose-built scripting language for network reconnaissance, OSINT, and security intelligence.**

[![Version](https://img.shields.io/badge/version-1.1.0-00ffcc?style=flat-square)](https://github.com/CzaxStudio/Fortress/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0077ff?style=flat-square)](#installation)
[![Language](https://img.shields.io/badge/language-.frt-00ccff?style=flat-square)](#language-reference)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

---

Fortress is a scripting language designed from the ground up for security professionals, OSINT analysts, and network engineers. Write readable, expressive scripts that perform DNS resolution, port scanning, geolocation, TLS inspection, certificate monitoring, and threat intelligence — then ship them as standalone executables that run on any machine with no dependencies.

# IMPORTANT
**Download From Releases for Linux and Mac**

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Building Executables](#building-executables)
- [Language Reference](#language-reference)
- [Built-in Functions](#built-in-functions)
- [Official Libraries](#official-libraries)
- [Package Manager](#package-manager)
- [Examples](#examples)
- [Contributing](#contributing)

---

## Features

- **Purpose-built syntax** — keywords like `probe`, `compute`, `capture`, `scan`, `each` designed for security workflows
- **21 network & OSINT builtins** — DNS, ports, geolocation, WHOIS, TLS, headers, reverse DNS, ASN, and more
- **Build to standalone exe** — compile any `.frt` script into a self-contained binary that needs no runtime
- **Package manager** — install, publish, and import `.frt` libraries with `fortress get`
- **Cross-platform** — runs on Windows, Linux, and macOS; zero external dependencies
- **No Go required** — users download a pre-built binary and run immediately

---

## Installation

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/CzaxStudio/Fortress/main/install.sh | bash
```

Or download and run manually:

```bash
chmod +x install.sh && ./install.sh
```

### Windows

Download `fortress-windows-amd64.exe` from the [Releases page](https://github.com/CzaxStudio/Fortress/releases), rename it to `fortress.exe`, and place it in a folder on your `PATH`.

Or use PowerShell:

```powershell
# Download
Invoke-WebRequest `
  -Uri "https://github.com/CzaxStudio/Fortress/releases/latest/download/fortress-windows-amd64.exe" `
  -OutFile "$env:LOCALAPPDATA\Fortress\fortress.exe"

# Add to PATH (run as Administrator)
[Environment]::SetEnvironmentVariable(
  "PATH", $env:PATH + ";$env:LOCALAPPDATA\Fortress", "Machine"
)
```

### Build from source

Only needed if you are modifying the interpreter itself. Requires [Go 1.21+](https://go.dev/dl/).

```bash
git clone https://github.com/CzaxStudio/Fortress
cd Fortress
go build -o fortress.exe .    # Windows
go build -o fortress .        # Linux / macOS
```

To cross-compile release binaries for all platforms at once:

```bash
chmod +x build-release.sh && ./build-release.sh
# Produces: dist/fortress-linux-amd64
#           dist/fortress-linux-arm64
#           dist/fortress-darwin-amd64
#           dist/fortress-darwin-arm64
#           dist/fortress-windows-amd64.exe
```

---

## Quick Start

Create a file called `recon.frt`:

```js
capture("Target domain: ") -> target

let dns  = resolve(target)
let geo  = geolocate(dns.ips[0])
let cert = certinfo(target)

compute("Host     : " -> dns.host)
compute("IP       : " -> dns.ips[0])
compute("Location : " -> geo.city -> ", " -> geo.country)
compute("Org      : " -> geo.org)
compute("TLS days : " -> str(cert.days_left) -> " remaining")
```

Run it:

```bash
fortress run recon.frt
```

Build it into a standalone executable that anyone can run:

```bash
fortress build recon.exe recon.frt
./recon.exe        # No Fortress installation needed on target machine
```

---

## CLI Reference

```
USAGE:
  fortress run <file.frt>                     Execute a Fortress script
  fortress build <output.exe> <file.frt>      Build a self-contained executable
  fortress build <output.exe> *               Bundle all .frt files in directory
  fortress create <file.frt>                  Create a new script from template
  fortress --version                          Show version info
  fortress --help                             Full language reference

PACKAGE MANAGER:
  fortress get file=<path.frtpkg>             Install a library from local package
  fortress get site=<name>                    Install a library from the registry
  fortress list                               List all installed libraries
  fortress info site=<name>                   Show library details
  fortress remove site=<name>                 Uninstall a library
  fortress <file.frt> create lib site=<name>  Publish a script as a library
  fortress * create lib site=<name>           Publish all .frt files as a library
```

---

## Building Executables

The `build` command produces a **standalone executable** — a copy of the Fortress interpreter with your script embedded inside it. The result runs on any machine with the same OS and architecture, no installation required.

```bash
# Single script → one exe
fortress build scanner.exe scanner.frt

# Entire project → one exe
# Entry point = main.frt if present, otherwise first .frt alphabetically
fortress build myapp.exe *
```

**On Windows**, executables launched by double-clicking will keep the console open with a `Press Enter to close...` prompt when the script finishes, so output is always readable.

> **Cross-platform builds:** `fortress build` always targets the current platform. To produce a Windows `.exe` from Linux, run the build step on Windows or set up a CI matrix with one job per platform.

---

## Language Reference

### Variables

```js
let target = "192.168.1.1"
let ports  = [80, 443, 8080]
let config = { "timeout": 500, "verbose": true }
```

### Output and input

```js
compute("Scanning: " -> target)        // print to console
capture("Enter target IP: ") -> ip    // read a line from stdin
```

### String concatenation  (`->`)

```js
let msg = "Host: " -> host -> "  open ports: " -> str(count)
```

### Probes (functions)

```js
probe gradeScore(score, max) {
    let pct = (score * 100) / max
    if pct >= 83 { return "A" }
    elif pct >= 66 { return "B" }
    elif pct >= 50 { return "C" }
    return "F"
}

let grade = gradeScore(74, 100)
compute("Grade: " -> grade)
```

### Control flow

```js
// C-style for loop
scan (let i = 0; i < len(ports); i++) {
    compute(str(ports[i]))
}

// For-each
each port in ports {
    compute("Port: " -> str(port))
}

// While
until scan.done {
    compute("Waiting...")
}

// Conditionals
if result.score >= 8 {
    compute("[CRITICAL]")
} elif result.score >= 4 {
    compute("[MEDIUM]")
} else {
    compute("[LOW]")
}
```

### Maps and lists

```js
let services = { "22": "SSH", "80": "HTTP", "443": "HTTPS" }
let found    = []

each p in scan.ports {
    if p.state == "open" and haskey(services, str(p.port)) {
        found = append(found, services[str(p.port)])
    }
}
compute("Services: " -> join(found, ", "))
```

### Saving and reporting

```js
// Save a key-value record to a file
save target -> "-result.json" {
    host:      target,
    open:      scan.open_count,
    scanned_at: now()
}

// Write a structured report
report "audit" as "json" {
    checked_at: now(),
    total:      len(domains),
    failed:     failCount
}
```

### Importing libraries

```js
import websec
websec.fullAudit("https://target.com")

import threatintel as ti
ti.iocReport("suspicious-domain.xyz")
```

---

## Built-in Functions

### Network & DNS

| Function | Description |
|---|---|
| `resolve(host)` | DNS resolution — A, AAAA, MX, NS, TXT, CNAME records |
| `portscan(host)` | TCP port scan with service banners |
| `portscan(host, ports, timeoutMs)` | Port scan with custom port list and timeout |
| `revdns(ip)` | Reverse DNS / PTR lookup |
| `subnet(cidr)` | Parse CIDR — network, broadcast, usable host range |
| `iprange(cidr, max)` | Expand CIDR to list of IP address strings |

### Intelligence & Certificates

| Function | Description |
|---|---|
| `geolocate(ip)` | IP geolocation — city, country, ISP, lat/lon, ASN |
| `whois(domain)` | WHOIS — registrar, created, expires, nameservers |
| `asnlookup(ip)` | ASN number, name, and country |
| `certinfo(domain)` | TLS certificate — subject, issuer, expiry, days left, SANs |
| `headers(url)` | HTTP response headers with security scoring |
| `pageintel(url)` | Page analysis — tech stack, links, emails, forms |

### String & List Utilities

| Function | Description |
|---|---|
| `upper(s)` / `lower(s)` | String case conversion |
| `str(v)` | Convert any value to string |
| `len(v)` | Length of string, list, or map |
| `contains(s, sub)` | Substring check |
| `slice(s, start, end)` | Substring extraction |
| `join(list, sep)` | Join list into a string |
| `append(list, item)` | Append item to list, returns new list |
| `haskey(map, key)` | Check if map contains a key |
| `type(v)` | Type name of a value (`"string"`, `"number"`, `"list"`, ...) |
| `now()` | Current timestamp as a string |

---



## Package Manager

The Fortress package manager handles installing, removing, and publishing `.frt` libraries. Libraries are stored locally and imported with the `import` keyword.

```bash
# Install
fortress get file=websec-1.0.0.frtpkg

# List installed
fortress list

# Show details
fortress info site=websec

# Remove
fortress remove site=websec
```

### Creating a library package

Write your probes in a `.frt` file, then publish it:

```bash
fortress mylib.frt create lib site=mylib
# → produces mylib-1.0.0.frtpkg
```

The `.frtpkg` format is a standard ZIP archive containing your `.frt` source files and a `fortress.pkg` JSON manifest. Share or distribute the file directly.

---

## Examples

### Quick domain snapshot

```js
capture("Domain: ") -> target
let dns  = resolve(target)
let cert = certinfo(target)
let geo  = geolocate(dns.ips[0])

compute("  IP       : " -> dns.ips[0])
compute("  Location : " -> geo.city -> ", " -> geo.country)
compute("  Org      : " -> geo.org)
compute("  TLS left : " -> str(cert.days_left) -> " days")
compute("  Expires  : " -> cert.not_after)
```

### Port watcher with danger alerts

```js
let danger = { "21": "FTP", "23": "Telnet", "3306": "MySQL",
               "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch" }

capture("Host: ") -> host
let scan = portscan(host)

each p in scan.ports {
    if p.state != "open" { continue }
    let port = str(p.port)
    if haskey(danger, port) {
        compute("  [!] " -> port -> " (" -> danger[port] -> ") — EXPOSED")
    } else {
        compute("  [+] " -> port -> "/" -> p.service)
    }
}
```

### Certificate expiry monitor

```js
let domains  = ["yourdomain.com", "api.yourdomain.com", "admin.yourdomain.com"]
let critDays = 14

each domain in domains {
    let cert = certinfo(domain)
    if cert.days_left < critDays {
        compute("  [!] " -> domain -> " — " -> str(cert.days_left) -> " days left — RENEW NOW")
    } else {
        compute("  [+] " -> domain -> " — OK (" -> str(cert.days_left) -> " days)")
    }
}
```

### Batch IP reputation triage

```js
let targets = ["8.8.8.8", "1.1.1.1", "185.220.101.1", "91.108.4.1"]

each ip in targets {
    let geo = geolocate(ip)
    let rev = revdns(ip)
    let ptr = lower(rev.ptr)

    let verdict = "CLEAN"
    if contains(ptr, "tor-exit") or contains(ptr, "scanner") { verdict = "HIGH RISK" }
    elif contains(lower(geo.org), "vpn") { verdict = "SUSPICIOUS" }

    compute("  " -> ip -> "  " -> geo.country -> "  " -> verdict)
}
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting large changes so we can discuss the approach first.

```bash
git clone https://github.com/CzaxStudio/Fortress
cd Fortress
go build -o fortress.exe .
fortress.exe run demo.frt
```

### Interpreter structure

| File | Role |
|---|---|
| `lexer.go` | Tokenizer — converts `.frt` source into a token stream |
| `parser.go` | Parser — builds an AST from the token stream |
| `interpreter1.go` | Core evaluator, standard library, import handling |
| `interpreter2.go` – `interpreter4.go`, `new.go` | All 21 network and OSINT built-in functions |
| `import.go` | Package manager — get, list, remove, publish |
| `main.go` | CLI dispatcher, `build` command, embedded-exe support |

### Adding a built-in function

1. Add the token to `lexer.go`
2. Add the parse case to `parser.go`
3. Implement the function in `interpreter2.go` (or a later split)
4. Add the dispatch case in `interpreter2.go`'s `callBuiltin` switch

---

<div align="center">

Made by [CzaxStudio](https://github.com/CzaxStudio) &nbsp;·&nbsp; MIT License

</div>
