// ══════════════════════════════════════════════════════════════════
//  ip-reputation.frt  —  Check reputation of multiple IPs at once
//  Usage: fortress run ip-reputation.frt
//  Add your IPs to the targets list below
// ══════════════════════════════════════════════════════════════════

let targets = [
    "8.8.8.8",
    "1.1.1.1",
    "91.108.4.1",
    "185.220.101.1"
]

compute("")
compute("  ╔══════════════════════════════════════════════════════╗")
compute("  ║  IP REPUTATION CHECKER — " -> str(len(targets)) -> " targets")
compute("  ╚══════════════════════════════════════════════════════╝")
compute("")
compute("  IP               COUNTRY     ORG                          VERDICT")
compute("  ──────────────────────────────────────────────────────────────────")

each ip in targets {
    let geo = geolocate(ip)
    let asn = asnlookup(ip)
    let rev = revdns(ip)

    // Simple heuristic scoring
    let score = 0
    let verdict = "CLEAN"

    // Datacenter / VPN ASN check
    let orgLow = lower(geo.org)
    if contains(orgLow, "vpn") or contains(orgLow, "proxy") { score = score + 20 }
    if contains(orgLow, "tor")   { score = score + 35 }

    // PTR record hints
    let ptr = lower(rev.ptr)
    if contains(ptr, "shodan")  { score = score + 40 }
    if contains(ptr, "censys")  { score = score + 40 }
    if contains(ptr, "scanner") { score = score + 30 }
    if contains(ptr, "tor-exit") or contains(ptr, "torexit") { score = score + 35 }

    if score >= 50  { verdict = "HIGH RISK" }
    elif score >= 20 { verdict = "SUSPICIOUS" }

    // Format columns
    let ipCol = ip
    scan (let i = len(ipCol); i < 17; i++) { ipCol = ipCol -> " " }
    let ccCol = geo.country_code -> " / " -> geo.city
    scan (let i = len(ccCol); i < 12; i++) { ccCol = ccCol -> " " }
    let orgCol = geo.org
    if len(orgCol) > 28 { orgCol = slice(orgCol, 0, 25) -> "..." }
    scan (let i = len(orgCol); i < 29; i++) { orgCol = orgCol -> " " }

    compute("  " -> ipCol -> ccCol -> " " -> orgCol -> verdict)
}

compute("")
compute("  ─────────────────────────────────────────────────────────────")
compute("  Tip: HIGH RISK IPs should be blocked at your firewall")
compute("  Full analysis: https://www.abuseipdb.com  |  https://otx.alienvault.com")
compute("")
