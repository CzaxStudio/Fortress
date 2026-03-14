// ══════════════════════════════════════════════════════════════════
//  port-watcher.frt  —  Scan a host and flag dangerous open ports
//  Usage: fortress run port-watcher.frt
// ══════════════════════════════════════════════════════════════════

capture("Target host or IP: ") -> target

let dangerPorts = {
    "21":    "FTP — plaintext credentials",
    "23":    "Telnet — plaintext shell, disable immediately",
    "445":   "SMB — EternalBlue attack surface",
    "3306":  "MySQL — database should not be public",
    "3389":  "RDP — BlueKeep / brute-force surface",
    "5432":  "PostgreSQL — database should not be public",
    "5900":  "VNC — remote desktop, often no auth",
    "6379":  "Redis — commonly auth-free",
    "8888":  "Jupyter — notebook often without credentials",
    "9200":  "Elasticsearch — commonly auth-free",
    "27017": "MongoDB — commonly auth-free"
}

compute("")
compute("  Scanning " -> target -> " ...")
let scan = portscan(target)
compute("")

compute("  ┌──────────────────────────────────────────────────┐")
compute("  │  PORT SCAN — " -> target)
compute("  └──────────────────────────────────────────────────┘")
compute("")
compute("  Open ports: " -> str(scan.open_count))
compute("")

let critFound = 0

each p in scan.ports {
    if p.state != "open" { continue }
    let port = str(p.port)
    let svc  = p.service

    if haskey(dangerPorts, port) {
        compute("  [✖] " -> port -> "/" -> svc -> " — DANGER: " -> dangerPorts[port])
        critFound = critFound + 1
    } else {
        compute("  [+] " -> port -> "/" -> svc)
    }
}

compute("")
compute("  ─────────────────────────────────────────────────")
if critFound > 0 {
    compute("  [!] " -> str(critFound) -> " dangerous port(s) found — review immediately")
} else {
    compute("  [+] No high-risk ports detected")
}
compute("")

// Save a quick report
save target to -> "-ports.txt" {
    host:       target,
    open_count: scan.open_count,
    dangerous:  critFound,
    scanned_at: now()
}
