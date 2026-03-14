// ══════════════════════════════════════════════════════════════════
//  domain-recon.frt  —  Quick domain reconnaissance
//  Usage: fortress run domain-recon.frt
// ══════════════════════════════════════════════════════════════════

capture("Target domain: ") -> target

let dns  = resolve(target)
let wo   = whois(target)
let cert = certinfo(target)
let geo  = geolocate(dns.ips[0])

compute("")
compute("  ┌──────────────────────────────────────────────────┐")
compute("  │  DOMAIN RECON — " -> target)
compute("  └──────────────────────────────────────────────────┘")

// ── DNS ───────────────────────────────────────────────────────────
compute("")
compute("  DNS")
compute("  ─────────────────────────────────────────────────")
each ip in dns.ips  { compute("    A        : " -> ip) }
each mx in dns.mx   { compute("    MX       : " -> mx) }
each ns in dns.ns   { compute("    NS       : " -> ns) }
if dns.cname != ""  { compute("    CNAME    : " -> dns.cname) }

// ── WHOIS ─────────────────────────────────────────────────────────
compute("")
compute("  WHOIS")
compute("  ─────────────────────────────────────────────────")
compute("    Registrar  : " -> wo.registrar)
compute("    Created    : " -> wo.created)
compute("    Expires    : " -> wo.expires)

// ── TLS CERTIFICATE ───────────────────────────────────────────────
compute("")
compute("  CERTIFICATE")
compute("  ─────────────────────────────────────────────────")
compute("    Subject    : " -> cert.subject)
compute("    Issuer     : " -> cert.issuer)
compute("    Expires    : " -> cert.not_after)
compute("    Days left  : " -> str(cert.days_left))

if cert.days_left < 30 {
    compute("    [!] Certificate expires soon — renew immediately!")
} elif cert.days_left < 0 {
    compute("    [✖] Certificate is EXPIRED")
} else {
    compute("    [+] Certificate is valid")
}

// ── HOSTING ───────────────────────────────────────────────────────
compute("")
compute("  HOSTING")
compute("  ─────────────────────────────────────────────────")
compute("    IP         : " -> dns.ips[0])
compute("    Country    : " -> geo.country)
compute("    City       : " -> geo.city)
compute("    ISP / Org  : " -> geo.org)
compute("")
