// ══════════════════════════════════════════════════════════════════
//  cert-monitor.frt  —  TLS certificate expiry monitor
//  Usage: fortress run cert-monitor.frt
//  Add your domains to the list below to watch their certs
// ══════════════════════════════════════════════════════════════════

let domains = [
    "google.com",
    "cloudflare.com",
    "github.com",
    "example.com"
]

let warnDays  = 30   // amber warning threshold
let critDays  = 7    // red critical threshold

compute("")
compute("  ┌──────────────────────────────────────────────────────┐")
compute("  │  TLS CERTIFICATE MONITOR — " -> str(len(domains)) -> " domain(s)")
compute("  └──────────────────────────────────────────────────────┘")
compute("")

let expiredCount = 0
let critCount    = 0
let warnCount    = 0
let okCount      = 0

each domain in domains {
    let cert = certinfo(domain)

    let status = ""
    let icon   = ""

    if cert.error != "" {
        status = "ERROR — " -> cert.error
        icon   = "[✖]"
        expiredCount = expiredCount + 1
    } elif cert.days_left < 0 {
        status = "EXPIRED " -> str(cert.days_left * -1) -> " days ago"
        icon   = "[✖]"
        expiredCount = expiredCount + 1
    } elif cert.days_left <= critDays {
        status = "CRITICAL — " -> str(cert.days_left) -> " days left"
        icon   = "[!]"
        critCount = critCount + 1
    } elif cert.days_left <= warnDays {
        status = "WARNING  — " -> str(cert.days_left) -> " days left"
        icon   = "[~]"
        warnCount = warnCount + 1
    } else {
        status = "OK — " -> str(cert.days_left) -> " days  (" -> cert.not_after -> ")"
        icon   = "[+]"
        okCount = okCount + 1
    }

    // Pad domain column to 22 chars
    let domCol = domain
    scan (let i = len(domCol); i < 22; i++) { domCol = domCol -> " " }

    compute("  " -> icon -> " " -> domCol -> "  " -> status)
}

compute("")
compute("  ─────────────────────────────────────────────────────")
compute("  Summary:")
compute("    [+] Valid   : " -> str(okCount))
compute("    [~] Warning : " -> str(warnCount) -> "  (< " -> str(warnDays) -> " days)")
compute("    [!] Critical: " -> str(critCount) -> "  (< " -> str(critDays) -> " days)")
compute("    [✖] Expired : " -> str(expiredCount))
compute("")

if critCount > 0 or expiredCount > 0 {
    compute("  ACTION REQUIRED — renew certificates listed above immediately")
    compute("")
}

// Persist results so you can diff over time
report "cert-monitor" as "json" {
    checked_at:    now(),
    total:         len(domains),
    ok:            okCount,
    warning:       warnCount,
    critical:      critCount,
    expired:       expiredCount
}
