package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── 17. dnsbrute() — Subdomain Enumeration ──────────────────────────────────
// Resolves common subdomains concurrently and returns live ones with IPs.

func (interp *Interpreter) netDNSBrute(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("dnsbrute() requires a base domain")
	}
	domain := strings.TrimSpace(args[0].Display())
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]

	// Optional custom wordlist; otherwise use built-in
	wordlist := dnsbruteWordlist
	if len(args) >= 2 && args[1].Type == ValList {
		wordlist = nil
		for _, w := range args[1].ListVal {
			wordlist = append(wordlist, w.Display())
		}
	}

	// Concurrency limit
	type result struct {
		sub   string
		fqdn  string
		ips   []string
		cname string
	}

	sem := make(chan struct{}, 40) // 40 concurrent goroutines
	ch := make(chan result, len(wordlist))
	var wg sync.WaitGroup

	for _, w := range wordlist {
		wg.Add(1)
		sub := w
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := sub + "." + domain
			addrs, err := net.LookupHost(fqdn)
			if err != nil {
				ch <- result{}
				return
			}
			cname, _ := net.LookupCNAME(fqdn)
			if cname == fqdn+"." {
				cname = ""
			}
			cname = strings.TrimSuffix(cname, ".")
			ch <- result{sub: sub, fqdn: fqdn, ips: addrs, cname: cname}
		}()
	}

	go func() { wg.Wait(); close(ch) }()

	var found []*Value
	for r := range ch {
		if r.fqdn == "" {
			continue
		}
		ipVals := make([]*Value, len(r.ips))
		for i, ip := range r.ips {
			ipVals[i] = strVal(ip)
		}
		entry := mapVal(map[string]*Value{
			"subdomain": strVal(r.sub),
			"fqdn":      strVal(r.fqdn),
			"ips":       listVal(ipVals),
			"ip": strVal(func() string {
				if len(r.ips) > 0 {
					return r.ips[0]
				}
				return ""
			}()),
			"cname": strVal(r.cname),
		})
		found = append(found, entry)
	}

	// Sort alphabetically by subdomain
	sort.Slice(found, func(i, j int) bool {
		return found[i].MapVal["fqdn"].StrVal < found[j].MapVal["fqdn"].StrVal
	})

	if found == nil {
		found = []*Value{}
	}

	return mapVal(map[string]*Value{
		"domain":      strVal(domain),
		"checked":     intVal(int64(len(wordlist))),
		"found":       listVal(found),
		"found_count": intVal(int64(len(found))),
		"error":       strVal(""),
	}), nil
}

var dnsbruteWordlist = []string{
	"www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
	"ns1", "ns2", "ns3", "dns", "dns1", "dns2",
	"admin", "administrator", "cpanel", "whm", "plesk", "panel",
	"api", "api2", "v1", "v2", "v3", "rest",
	"dev", "develop", "development", "staging", "stage", "stg",
	"test", "testing", "qa", "uat", "sandbox", "demo",
	"prod", "production", "live",
	"blog", "news", "forum", "forums", "community", "wiki",
	"shop", "store", "cart", "checkout", "payment",
	"cdn", "cdn1", "cdn2", "static", "assets", "img", "images",
	"video", "media", "files", "uploads", "download", "downloads",
	"app", "apps", "mobile", "m", "wap",
	"portal", "dashboard", "console", "control",
	"vpn", "remote", "citrix", "owa", "exchange",
	"git", "gitlab", "github", "svn", "jenkins", "ci", "build",
	"jira", "confluence", "docs", "help", "support", "kb",
	"monitor", "monitoring", "grafana", "kibana", "elastic",
	"db", "database", "mysql", "postgres", "redis", "mongo",
	"smtp1", "smtp2", "mx1", "mx2", "mail1", "mail2",
	"autodiscover", "autoconfig",
	"secure", "ssl", "login", "auth", "sso",
	"beta", "alpha", "preview", "new", "old", "legacy",
	"internal", "intranet", "corp", "office",
	"aws", "cloud", "azure", "gcp",
	"status", "health", "ping", "uptime",
	"proxy", "lb", "loadbalancer", "gateway", "gw",
	"chat", "slack", "meet", "video",
	"analytics", "stats", "tracking",
}

// ─── 18. sslgrade() — SSL/TLS Security Grading ───────────────────────────────
// Performs an SSL Labs-style assessment: protocol support, cipher strength,
// certificate validity, HSTS, key size, and overall grade A-F.

func (interp *Interpreter) netSSLGrade(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("sslgrade() requires a hostname")
	}
	host := strings.TrimSpace(args[0].Display())
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	errResult := func(msg string) *Value {
		return mapVal(map[string]*Value{
			"host": strVal(host), "grade": strVal("T"), "error": strVal(msg),
			"score": intVal(0), "issues": listVal([]*Value{}),
		})
	}

	score := 100
	var issues, positives []*Value
	addIssue := func(sev, msg string, penalty int) {
		issues = append(issues, strVal("["+sev+"] "+msg))
		score -= penalty
	}
	addPositive := func(msg string) {
		positives = append(positives, strVal("[+] "+msg))
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// ── Test TLS 1.3 ──────────────────────────────────────────────────────
	hasTLS13 := false
	conn13, err13 := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err13 == nil {
		conn13.Close()
		hasTLS13 = true
	}

	// ── Test TLS 1.2 ──────────────────────────────────────────────────────
	hasTLS12 := false
	conn12, err12 := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	})
	if err12 == nil {
		conn12.Close()
		hasTLS12 = true
	}

	// ── Test TLS 1.0 (deprecated) ─────────────────────────────────────────
	hasTLS10 := false
	conn10, err10 := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
		InsecureSkipVerify: true,
	})
	if err10 == nil {
		conn10.Close()
		hasTLS10 = true
	}

	// ── Test TLS 1.1 (deprecated) ─────────────────────────────────────────
	hasTLS11 := false
	conn11, err11 := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11,
		InsecureSkipVerify: true,
	})
	if err11 == nil {
		conn11.Close()
		hasTLS11 = true
	}

	if !hasTLS12 && !hasTLS13 {
		return errResult("host does not support TLS 1.2 or 1.3"), nil
	}

	// ── Get full connection state for cipher/cert analysis ────────────────
	mainConn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return errResult(err.Error()), nil
	}
	defer mainConn.Close()
	state := mainConn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errResult("no certificates presented"), nil
	}
	cert := certs[0]
	daysLeft := int64(time.Until(cert.NotAfter).Hours() / 24)

	// ── Protocol scoring ──────────────────────────────────────────────────
	if hasTLS13 {
		addPositive("TLS 1.3 supported (optimal)")
	}
	if hasTLS12 {
		addPositive("TLS 1.2 supported")
	}
	if hasTLS10 {
		addIssue("HIGH", "TLS 1.0 enabled — POODLE/BEAST attack surface (+20 pts)", 20)
	}
	if hasTLS11 {
		addIssue("MED", "TLS 1.1 enabled — deprecated, disable recommended (+10 pts)", 10)
	}
	if !hasTLS13 && hasTLS12 {
		addIssue("LOW", "TLS 1.3 not supported — upgrade recommended (-5 pts)", 5)
	}

	// ── Cipher suite assessment ───────────────────────────────────────────
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	weakCiphers := []string{"RC4", "3DES", "NULL", "EXPORT", "anon", "DES"}
	cipherWeak := false
	for _, wc := range weakCiphers {
		if strings.Contains(cipherName, wc) {
			cipherWeak = true
			addIssue("CRIT", "Weak cipher in use: "+cipherName+" (-30 pts)", 30)
			break
		}
	}
	if !cipherWeak {
		addPositive("Negotiated cipher: " + cipherName)
	}

	// ── Certificate validity ──────────────────────────────────────────────
	certValid := true
	if daysLeft < 0 {
		addIssue("CRIT", fmt.Sprintf("Certificate EXPIRED %d days ago (-50 pts)", -daysLeft), 50)
		certValid = false
	} else if daysLeft < 14 {
		addIssue("CRIT", fmt.Sprintf("Certificate expires in %d days — URGENT renewal (-20 pts)", daysLeft), 20)
	} else if daysLeft < 30 {
		addIssue("HIGH", fmt.Sprintf("Certificate expires in %d days — renew soon (-10 pts)", daysLeft), 10)
	} else {
		addPositive(fmt.Sprintf("Certificate valid for %d more days", daysLeft))
	}

	// ── Key size ──────────────────────────────────────────────────────────
	keyAlgo, keySize := certKeyInfo(cert)
	if keyAlgo == "RSA" && keySize < 2048 {
		addIssue("CRIT", fmt.Sprintf("Weak RSA key: %d bits (minimum 2048) (-30 pts)", keySize), 30)
	} else if keyAlgo == "RSA" && keySize >= 4096 {
		addPositive(fmt.Sprintf("Strong key: %s-%d", keyAlgo, keySize))
	} else {
		addPositive(fmt.Sprintf("Key: %s-%d", keyAlgo, keySize))
	}

	// ── Chain validation ──────────────────────────────────────────────────
	if len(certs) < 2 {
		addIssue("HIGH", "Incomplete certificate chain — intermediate(s) missing (-15 pts)", 15)
	} else {
		addPositive(fmt.Sprintf("Full chain presented (%d certs)", len(certs)))
	}

	// ── HSTS check via HTTP headers ───────────────────────────────────────
	hstsFound := false
	hstsPreload := false
	hstsIncludeSub := false
	req, reqErr := http.NewRequest("HEAD", "https://"+host, nil)
	if reqErr == nil {
		req.Header.Set("User-Agent", "Fortress/1.0")
		resp, respErr := interp.httpCli.Do(req)
		if respErr == nil {
			defer resp.Body.Close()
			if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
				hstsFound = true
				hstsPreload = strings.Contains(hsts, "preload")
				hstsIncludeSub = strings.Contains(hsts, "includeSubDomains")

				// Parse max-age
				for _, part := range strings.Split(hsts, ";") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(strings.ToLower(part), "max-age=") {
						ageStr := strings.TrimPrefix(strings.ToLower(part), "max-age=")
						if age, aerr := strconv.ParseInt(ageStr, 10, 64); aerr == nil {
							if age < 2592000 { // < 30 days
								addIssue("MED", fmt.Sprintf("HSTS max-age too short: %d seconds (-5 pts)", age), 5)
							} else {
								addPositive(fmt.Sprintf("HSTS max-age: %d days", age/86400))
							}
						}
					}
				}
			}
		}
	}
	if !hstsFound {
		addIssue("HIGH", "HSTS header absent — browser can be downgraded to HTTP (-15 pts)", 15)
	} else {
		if !hstsPreload {
			addIssue("LOW", "HSTS missing 'preload' directive (-3 pts)", 3)
		} else {
			addPositive("HSTS preload directive present")
		}
		if !hstsIncludeSub {
			addIssue("LOW", "HSTS missing 'includeSubDomains' (-3 pts)", 3)
		} else {
			addPositive("HSTS includeSubDomains present")
		}
	}

	// ── OCSP stapling (best effort) ───────────────────────────────────────
	if state.OCSPResponse != nil && len(state.OCSPResponse) > 0 {
		addPositive("OCSP stapling active")
	} else {
		addIssue("LOW", "OCSP stapling not detected (-2 pts)", 2)
	}

	// ── Certificate Transparency ──────────────────────────────────────────
	if len(cert.OCSPServer) > 0 {
		addPositive("OCSP responder configured: " + cert.OCSPServer[0])
	}

	// ── TLS version negotiated ────────────────────────────────────────────
	tlsVerStr := tlsVersionString(state.Version)

	// ── Final grade ───────────────────────────────────────────────────────
	if score < 0 {
		score = 0
	}
	grade := "A+"
	switch {
	case score < 20 || !certValid:
		grade = "F"
	case score < 35:
		grade = "D"
	case score < 50:
		grade = "C"
	case score < 65:
		grade = "B-"
	case score < 75:
		grade = "B"
	case score < 85:
		grade = "B+"
	case score < 92:
		grade = "A-"
	case score < 97:
		grade = "A"
	default:
		grade = "A+"
	}
	if !hasTLS13 && grade == "A+" {
		grade = "A"
	}
	if hasTLS10 && (grade == "A+" || grade == "A" || grade == "A-" || grade == "B+") {
		grade = "B" // cap at B if TLS 1.0 still enabled
	}

	if issues == nil {
		issues = []*Value{}
	}
	if positives == nil {
		positives = []*Value{}
	}

	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	return mapVal(map[string]*Value{
		"host":            strVal(host),
		"grade":           strVal(grade),
		"score":           intVal(int64(score)),
		"tls_version":     strVal(tlsVerStr),
		"cipher":          strVal(cipherName),
		"tls13":           boolVal(hasTLS13),
		"tls12":           boolVal(hasTLS12),
		"tls11":           boolVal(hasTLS11),
		"tls10":           boolVal(hasTLS10),
		"cert_subject":    strVal(cert.Subject.CommonName),
		"cert_issuer_org": strVal(issuerOrg),
		"cert_days_left":  intVal(daysLeft),
		"cert_expired":    boolVal(daysLeft < 0),
		"cert_valid":      boolVal(certValid),
		"key_algo":        strVal(keyAlgo),
		"key_size":        intVal(int64(keySize)),
		"chain_len":       intVal(int64(len(certs))),
		"hsts":            boolVal(hstsFound),
		"hsts_preload":    boolVal(hstsPreload),
		"hsts_subdomains": boolVal(hstsIncludeSub),
		"issues":          listVal(issues),
		"issue_count":     intVal(int64(len(issues))),
		"positives":       listVal(positives),
		"positive_count":  intVal(int64(len(positives))),
		"error":           strVal(""),
	}), nil
}

// ─── 19. pastefind() — Paste/Leak Site Intelligence ──────────────────────────
// Searches publicly indexed paste and leak aggregator APIs for mentions of
// a target (email, domain, IP, username). Returns hits with source, title, date.

func (interp *Interpreter) netPasteFind(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("pastefind() requires a search term (email, domain, IP, or username)")
	}
	query := strings.TrimSpace(args[0].Display())

	type Hit struct {
		source string
		title  string
		url    string
		date   string
		size   string
		syntax string
	}
	var hits []Hit
	var searchErrs []string

	// ── 1. Psbdmp.ws — public Pastebin dump search ───────────────────────
	psbURL := "https://psbdmp.ws/api/search/" + strings.ReplaceAll(query, " ", "+")
	psbData, psbErr := interp.getJSON(psbURL)
	if psbErr == nil {
		if arr, ok := psbData["data"].([]interface{}); ok {
			for i, item := range arr {
				if i >= 10 {
					break
				}
				if m, ok := item.(map[string]interface{}); ok {
					id := fmt.Sprintf("%v", m["id"])
					title := fmt.Sprintf("%v", m["tags"])
					date := fmt.Sprintf("%v", m["time"])
					size := fmt.Sprintf("%v", m["length"])
					if title == "<nil>" || title == "null" {
						title = "(no title)"
					}
					hits = append(hits, Hit{
						source: "Pastebin (via psbdmp.ws)",
						title:  title,
						url:    "https://pastebin.com/" + id,
						date:   date,
						size:   size + " chars",
					})
				}
			}
		}
	} else {
		searchErrs = append(searchErrs, "psbdmp.ws: "+psbErr.Error())
	}

	// ── 2. GitHub code search (public API, no auth, limited) ─────────────
	ghURL := "https://api.github.com/search/code?q=" + strings.ReplaceAll(query, "@", "%40") +
		"&per_page=5&sort=indexed"
	req, _ := http.NewRequest("GET", ghURL, nil)
	req.Header.Set("User-Agent", "Fortress/1.0 OSINT-Engine")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	ghResp, ghErr := interp.httpCli.Do(req)
	if ghErr == nil {
		defer ghResp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(ghResp.Body, 512*1024))
		var ghData map[string]interface{}
		if json.Unmarshal(body, &ghData) == nil {
			if items, ok := ghData["items"].([]interface{}); ok {
				for _, item := range items {
					if m, ok := item.(map[string]interface{}); ok {
						name := fmt.Sprintf("%v", m["name"])
						htmlURL := fmt.Sprintf("%v", m["html_url"])
						repo := ""
						if r, ok := m["repository"].(map[string]interface{}); ok {
							repo = fmt.Sprintf("%v", r["full_name"])
						}
						hits = append(hits, Hit{
							source: "GitHub Code",
							title:  repo + " / " + name,
							url:    htmlURL,
							date:   "",
							size:   "",
						})
					}
				}
			}
			if total, ok := ghData["total_count"].(float64); ok {
				if total > 0 {
					// already added individual hits above
				} else {
					searchErrs = append(searchErrs, "GitHub: no code results")
				}
			}
		}
	} else {
		searchErrs = append(searchErrs, "GitHub: "+ghErr.Error())
	}

	// ── 3. IntelX (public search, no key, limited results) ───────────────
	// Uses the public selector search to find indexed records
	intelxURL := "https://2.intelx.io/intelligent/search?q=" +
		strings.ReplaceAll(query, "@", "%40") + "&maxresults=5"
	ixReq, _ := http.NewRequest("GET", intelxURL, nil)
	ixReq.Header.Set("User-Agent", "Fortress/1.0")
	ixReq.Header.Set("x-key", "PUBLIC")
	ixResp, ixErr := interp.httpCli.Do(ixReq)
	if ixErr == nil {
		defer ixResp.Body.Close()
		ixBody, _ := io.ReadAll(io.LimitReader(ixResp.Body, 256*1024))
		var ixData map[string]interface{}
		if json.Unmarshal(ixBody, &ixData) == nil {
			if records, ok := ixData["records"].([]interface{}); ok {
				for _, rec := range records {
					if m, ok := rec.(map[string]interface{}); ok {
						name := fmt.Sprintf("%v", m["name"])
						stype := fmt.Sprintf("%v", m["stype"])
						date := fmt.Sprintf("%v", m["date"])
						hits = append(hits, Hit{
							source: "IntelligenceX",
							title:  name,
							url:    "https://intelx.io/?s=" + strings.ReplaceAll(query, "@", "%40"),
							date:   date,
							size:   "type:" + stype,
						})
					}
				}
			}
		}
	} else {
		searchErrs = append(searchErrs, "IntelX: "+ixErr.Error())
	}

	// ── 4. BreachDirectory (public check for emails) ──────────────────────
	if strings.Contains(query, "@") {
		bdURL := "https://breachdirectory.p.rapidapi.com/?func=auto&term=" +
			strings.ReplaceAll(query, "@", "%40")
		bdReq, _ := http.NewRequest("GET", bdURL, nil)
		bdReq.Header.Set("User-Agent", "Fortress/1.0")
		bdResp, bdErr := interp.httpCli.Do(bdReq)
		if bdErr == nil {
			defer bdResp.Body.Close()
			bdBody, _ := io.ReadAll(io.LimitReader(bdResp.Body, 256*1024))
			var bdData map[string]interface{}
			if json.Unmarshal(bdBody, &bdData) == nil {
				if success, ok := bdData["success"].(bool); ok && success {
					count := 0
					if c, ok := bdData["found"].(float64); ok {
						count = int(c)
					}
					if count > 0 {
						hits = append(hits, Hit{
							source: "BreachDirectory",
							title:  fmt.Sprintf("%d breach entries found for %s", count, query),
							url:    "https://breachdirectory.org/",
							date:   "",
							size:   fmt.Sprintf("%d records", count),
						})
					}
				}
			}
		}
	}

	// Build result list
	hitVals := make([]*Value, 0, len(hits))
	for _, h := range hits {
		hitVals = append(hitVals, mapVal(map[string]*Value{
			"source": strVal(h.source),
			"title":  strVal(h.title),
			"url":    strVal(h.url),
			"date":   strVal(h.date),
			"size":   strVal(h.size),
		}))
	}

	errVals := make([]*Value, len(searchErrs))
	for i, e := range searchErrs {
		errVals[i] = strVal(e)
	}

	// Summary note
	note := "Results from: Pastebin (psbdmp.ws), GitHub, IntelligenceX"
	if strings.Contains(query, "@") {
		note += ", BreachDirectory"
	}
	note += ". For complete results use a paid API key."

	return mapVal(map[string]*Value{
		"query":       strVal(query),
		"hits":        listVal(hitVals),
		"hit_count":   intVal(int64(len(hitVals))),
		"search_errs": listVal(errVals),
		"note":        strVal(note),
		"error":       strVal(""),
	}), nil
}
