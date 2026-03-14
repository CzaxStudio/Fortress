package main

// ─── new.go — New Fortress DSL builtins ──────────────────────────────────────
//
//  20. httpfuzz()  — HTTP path/directory fuzzer
//      Probes a target URL for hidden paths, admin panels, config files,
//      backup files, and common web app endpoints. Returns status codes,
//      sizes, and redirect targets for each hit.
//
//  21. tlschain()  — Full TLS certificate chain tracer
//      Connects to a host and walks the full X.509 chain from leaf to root,
//      extracting subject, issuer, key type, validity, SANs, policy OIDs,
//      and trust anchor classification for each certificate in the chain.
//
// Both are registered in interpreter2.go's evalNetBuiltin dispatcher.

import (
	"crypto/tls"
	"crypto/x509"
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

// ─── 20. httpfuzz() — HTTP Path / Directory Fuzzer ───────────────────────────

func (interp *Interpreter) netHTTPFuzz(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("httpfuzz() requires a target URL")
	}
	rawURL := strings.TrimSpace(args[0].Display())
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	rawURL = strings.TrimRight(rawURL, "/")

	// Optional custom wordlist
	wordlist := httpFuzzWordlist
	if len(args) >= 2 && args[1].Type == ValList {
		wordlist = nil
		for _, w := range args[1].ListVal {
			wordlist = append(wordlist, w.Display())
		}
	}

	// Concurrency
	type result struct {
		path     string
		status   int
		size     int64
		location string
		title    string
		hit      bool
	}

	sem := make(chan struct{}, 20)
	ch := make(chan result, len(wordlist))
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow — capture redirect
		},
	}

	for _, path := range wordlist {
		wg.Add(1)
		p := path
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := rawURL + "/" + strings.TrimPrefix(p, "/")
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				ch <- result{path: p}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Fortress/1.0)")
			req.Header.Set("Accept", "text/html,*/*")

			resp, err := client.Do(req)
			if err != nil {
				ch <- result{path: p}
				return
			}
			defer resp.Body.Close()

			// Read small portion for title extraction
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			bodyStr := string(body)

			// Extract title
			title := ""
			if idx := strings.Index(strings.ToLower(bodyStr), "<title"); idx >= 0 {
				rest := bodyStr[idx:]
				if s := strings.Index(rest, ">"); s >= 0 {
					rest = rest[s+1:]
					if e := strings.Index(strings.ToLower(rest), "</title"); e >= 0 {
						title = strings.TrimSpace(rest[:e])
						if len(title) > 60 {
							title = title[:60] + "..."
						}
					}
				}
			}

			location := resp.Header.Get("Location")
			clen := resp.ContentLength
			if clen < 0 {
				clen = int64(len(body))
			}

			// Only report interesting status codes
			interesting := resp.StatusCode == 200 ||
				resp.StatusCode == 201 ||
				resp.StatusCode == 204 ||
				resp.StatusCode == 301 ||
				resp.StatusCode == 302 ||
				resp.StatusCode == 307 ||
				resp.StatusCode == 401 ||
				resp.StatusCode == 403 ||
				resp.StatusCode == 405 ||
				resp.StatusCode == 500

			if interesting {
				ch <- result{
					path:     p,
					status:   resp.StatusCode,
					size:     clen,
					location: location,
					title:    title,
					hit:      true,
				}
			} else {
				ch <- result{path: p, hit: false}
			}
		}()
	}

	go func() { wg.Wait(); close(ch) }()

	var hits []*Value
	statusCounts := map[int]int{}

	for r := range ch {
		if !r.hit {
			continue
		}
		statusCounts[r.status]++
		entry := mapVal(map[string]*Value{
			"path":     strVal(r.path),
			"url":      strVal(rawURL + "/" + strings.TrimPrefix(r.path, "/")),
			"status":   intVal(int64(r.status)),
			"size":     intVal(r.size),
			"location": strVal(r.location),
			"title":    strVal(r.title),
		})
		hits = append(hits, entry)
	}

	// Sort by status code then path
	sort.Slice(hits, func(i, j int) bool {
		si := hits[i].MapVal["status"].IntVal
		sj := hits[j].MapVal["status"].IntVal
		if si != sj {
			return si < sj
		}
		return hits[i].MapVal["path"].StrVal < hits[j].MapVal["path"].StrVal
	})

	// Build status summary
	var statusSummary []*Value
	for code, count := range statusCounts {
		label := httpStatusLabel(code)
		statusSummary = append(statusSummary, strVal(
			fmt.Sprintf("%d %s: %d path(s)", code, label, count)))
	}
	sort.Slice(statusSummary, func(i, j int) bool {
		return statusSummary[i].StrVal < statusSummary[j].StrVal
	})

	if hits == nil {
		hits = []*Value{}
	}
	if statusSummary == nil {
		statusSummary = []*Value{}
	}

	return mapVal(map[string]*Value{
		"target":         strVal(rawURL),
		"probed":         intVal(int64(len(wordlist))),
		"hits":           listVal(hits),
		"hit_count":      intVal(int64(len(hits))),
		"status_summary": listVal(statusSummary),
		"error":          strVal(""),
	}), nil
}

func httpStatusLabel(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found (Redirect)"
	case 307:
		return "Temporary Redirect"
	case 401:
		return "Unauthorized (Auth Required)"
	case 403:
		return "Forbidden (Exists but blocked)"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	default:
		return strconv.Itoa(code)
	}
}

// Built-in wordlist — common web paths, admin panels, config, backups, APIs
var httpFuzzWordlist = []string{
	// Admin panels
	"admin", "admin/", "administrator", "admin/login", "admin/dashboard",
	"admin/index.php", "admin/login.php", "admin.php", "admin.html",
	"wp-admin", "wp-admin/", "wp-login.php", "wp-admin/admin-ajax.php",
	"phpmyadmin", "phpmyadmin/", "pma", "mysql", "dbadmin",
	"cpanel", "whm", "plesk", "panel", "controlpanel",
	"manager", "management", "webmaster",
	// Auth endpoints
	"login", "login.php", "login.html", "signin", "sign-in",
	"auth", "auth/login", "authenticate", "sso", "oauth",
	"logout", "register", "signup", "sign-up",
	// APIs
	"api", "api/v1", "api/v2", "api/v3", "api/index",
	"api/users", "api/admin", "api/login", "api/config",
	"api/status", "api/health", "api/docs", "api/swagger",
	"rest", "graphql", "v1", "v2",
	"swagger", "swagger-ui", "swagger.json", "swagger.yaml",
	"openapi.json", "openapi.yaml",
	// Config & sensitive files
	".env", ".env.local", ".env.production", ".env.backup",
	"config.php", "config.yml", "config.yaml", "config.json",
	"configuration.php", "settings.php", "settings.py",
	"web.config", "app.config", "application.properties",
	"database.yml", "database.php", "db.php",
	".git/HEAD", ".git/config", ".svn/entries",
	".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
	"crossdomain.xml", "clientaccesspolicy.xml",
	// Backup files
	"backup", "backup.zip", "backup.tar.gz", "backup.sql",
	"backup.php", "db_backup.sql", "database.sql",
	"site.zip", "www.zip", "html.zip", "public.zip",
	"old", "bak", "temp", "tmp",
	// Logs & debug
	"logs", "log", "error.log", "access.log", "debug.log",
	"error_log", "php_errors.log", "laravel.log",
	"phpinfo.php", "info.php", "test.php", "debug.php",
	// Dev tools
	"console", "shell", "terminal", "cmd",
	"jenkins", "jenkins/", "ci", "build", "deploy",
	"git", "gitlab", "bitbucket",
	"jira", "confluence", "wiki",
	// Health / status
	"health", "healthz", "health/live", "health/ready",
	"status", "ping", "alive", "ready",
	"metrics", "actuator", "actuator/health", "actuator/env",
	// Common framework paths
	"wp-content/uploads/", "wp-includes/",
	"vendor/", "node_modules/",
	"uploads", "upload", "files", "media", "assets",
	"static", "public", "private", "secret",
	// Server info
	"server-status", "server-info",
	"nginx_status", "fpm_status",
}

// ─── 21. tlschain() — Full Certificate Chain Tracer ──────────────────────────

func (interp *Interpreter) netTLSChain(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("tlschain() requires a hostname")
	}
	host := strings.TrimSpace(args[0].Display())
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	port := "443"
	if len(args) >= 2 {
		port = args[1].Display()
	}

	errResult := func(msg string) *Value {
		return mapVal(map[string]*Value{
			"host":        strVal(host),
			"chain":       listVal([]*Value{}),
			"chain_len":   intVal(0),
			"trust_valid": boolVal(false),
			"error":       strVal(msg),
		})
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// First attempt: verified connection
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		ServerName: host,
	})
	trustValid := true
	if err != nil {
		// Retry insecure to still get the chain
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		trustValid = false
		if err != nil {
			return errResult(err.Error()), nil
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return errResult("no certificates in chain"), nil
	}

	// Walk every cert in the chain
	chainVals := make([]*Value, 0, len(certs))
	for i, cert := range certs {
		role := chainRole(i, len(certs))
		keyAlgo, keySize := certKeyInfo(cert)
		daysLeft := int64(time.Until(cert.NotAfter).Hours() / 24)

		// SANs (leaf cert only)
		sanList := make([]*Value, 0)
		if i == 0 {
			for _, s := range cert.DNSNames {
				sanList = append(sanList, strVal(s))
			}
			for _, ip := range cert.IPAddresses {
				sanList = append(sanList, strVal(ip.String()))
			}
		}

		// Subject alternative names count
		sanCount := int64(len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.URIs))

		// Policy OIDs (EV, DV, OV detection)
		var policyStrs []string
		for _, p := range cert.PolicyIdentifiers {
			policyStrs = append(policyStrs, p.String())
		}
		certType := classifyCertType(policyStrs)

		// Key usage
		keyUsages := certKeyUsages(cert)

		// Extended key usage
		extUsages := certExtKeyUsages(cert)

		// Is self-signed?
		isSelfSigned := cert.Subject.CommonName == cert.Issuer.CommonName &&
			cert.Subject.String() == cert.Issuer.String()

		// Is CA?
		isCA := cert.IsCA

		// Fingerprint (SHA-256 first 20 bytes hex)
		fp := certFingerprint(cert.Raw)

		// Subject org
		subjectOrg := ""
		if len(cert.Subject.Organization) > 0 {
			subjectOrg = cert.Subject.Organization[0]
		}
		issuerOrg := ""
		if len(cert.Issuer.Organization) > 0 {
			issuerOrg = cert.Issuer.Organization[0]
		}

		// Trust anchor classification
		trustAnchor := classifyTrustAnchor(cert.Issuer.CommonName, isCA, isSelfSigned)

		// OCSP / CRL
		ocsp := ""
		crl := ""
		if len(cert.OCSPServer) > 0 {
			ocsp = cert.OCSPServer[0]
		}
		if len(cert.CRLDistributionPoints) > 0 {
			crl = cert.CRLDistributionPoints[0]
		}

		certMap := mapVal(map[string]*Value{
			"index":          intVal(int64(i)),
			"role":           strVal(role),
			"cert_type":      strVal(certType),
			"subject_cn":     strVal(cert.Subject.CommonName),
			"subject_org":    strVal(subjectOrg),
			"issuer_cn":      strVal(cert.Issuer.CommonName),
			"issuer_org":     strVal(issuerOrg),
			"not_before":     strVal(cert.NotBefore.UTC().Format("2006-01-02")),
			"not_after":      strVal(cert.NotAfter.UTC().Format("2006-01-02")),
			"days_left":      intVal(daysLeft),
			"expired":        boolVal(daysLeft < 0),
			"key_algo":       strVal(keyAlgo),
			"key_size":       intVal(int64(keySize)),
			"sig_algo":       strVal(cert.SignatureAlgorithm.String()),
			"serial":         strVal(fmt.Sprintf("%X", cert.SerialNumber)[:min2(32, len(fmt.Sprintf("%X", cert.SerialNumber)))]),
			"version":        intVal(int64(cert.Version)),
			"is_ca":          boolVal(isCA),
			"is_self_signed": boolVal(isSelfSigned),
			"san_count":      intVal(sanCount),
			"sans":           listVal(sanList),
			"key_usage":      strVal(strings.Join(keyUsages, ", ")),
			"ext_key_usage":  strVal(strings.Join(extUsages, ", ")),
			"policies":       strVal(strings.Join(policyStrs, ", ")),
			"trust_anchor":   strVal(trustAnchor),
			"fingerprint":    strVal(fp),
			"ocsp_url":       strVal(ocsp),
			"crl_url":        strVal(crl),
		})
		chainVals = append(chainVals, certMap)
	}

	// Chain integrity check
	chainIntact := true
	chainIssue := ""
	for i := 0; i < len(certs)-1; i++ {
		if certs[i].Issuer.CommonName != certs[i+1].Subject.CommonName {
			chainIntact = false
			chainIssue = fmt.Sprintf("Gap between cert[%d] issuer and cert[%d] subject", i, i+1)
			break
		}
	}

	tlsVer := tlsVersionString(state.Version)
	cipher := tls.CipherSuiteName(state.CipherSuite)

	return mapVal(map[string]*Value{
		"host":         strVal(host),
		"port":         strVal(port),
		"tls_version":  strVal(tlsVer),
		"cipher":       strVal(cipher),
		"chain":        listVal(chainVals),
		"chain_len":    intVal(int64(len(chainVals))),
		"trust_valid":  boolVal(trustValid),
		"chain_intact": boolVal(chainIntact),
		"chain_issue":  strVal(chainIssue),
		"leaf_subject": strVal(certs[0].Subject.CommonName),
		"root_issuer":  strVal(certs[len(certs)-1].Issuer.CommonName),
		"error":        strVal(""),
	}), nil
}

func chainRole(i, total int) string {
	if i == 0 {
		return "Leaf (End-Entity)"
	}
	if i == total-1 {
		return "Root CA"
	}
	return fmt.Sprintf("Intermediate CA (%d)", i)
}

func classifyCertType(policies []string) string {
	evOIDs := map[string]bool{
		"2.23.140.1.1":                  true, // CAB Forum EV
		"1.3.6.1.4.1.34697.2.1":         true,
		"2.16.840.1.114028.10.1.2":      true, // Entrust EV
		"1.3.6.1.4.1.17326.10.14.2.1.2": true,
	}
	for _, p := range policies {
		if evOIDs[p] {
			return "EV (Extended Validation)"
		}
	}
	for _, p := range policies {
		if strings.Contains(p, "2.23.140.1.2") {
			return "OV (Organization Validation)"
		}
		if strings.Contains(p, "2.23.140.1.3") {
			return "DV (Domain Validation)"
		}
	}
	if len(policies) > 0 {
		return "DV (Domain Validation)"
	}
	return "Unknown"
}

func classifyTrustAnchor(issuerCN string, isCA, isSelfSigned bool) string {
	cn := strings.ToLower(issuerCN)
	switch {
	case isSelfSigned && isCA:
		return "Root CA (self-signed trust anchor)"
	case strings.Contains(cn, "let's encrypt") || strings.Contains(cn, "lets encrypt"):
		return "Let's Encrypt (ISRG)"
	case strings.Contains(cn, "digicert"):
		return "DigiCert"
	case strings.Contains(cn, "comodo") || strings.Contains(cn, "sectigo"):
		return "Sectigo/Comodo"
	case strings.Contains(cn, "globalsign"):
		return "GlobalSign"
	case strings.Contains(cn, "entrust"):
		return "Entrust"
	case strings.Contains(cn, "geotrust"):
		return "GeoTrust/DigiCert"
	case strings.Contains(cn, "godaddy") || strings.Contains(cn, "go daddy"):
		return "GoDaddy"
	case strings.Contains(cn, "thawte"):
		return "Thawte/DigiCert"
	case strings.Contains(cn, "amazon"):
		return "Amazon Trust Services"
	case strings.Contains(cn, "microsoft"):
		return "Microsoft PKI"
	case strings.Contains(cn, "google"):
		return "Google Trust Services"
	case strings.Contains(cn, "cloudflare"):
		return "Cloudflare PKI"
	case isCA:
		return "Certificate Authority"
	default:
		return "Intermediate / Unknown"
	}
}

func certKeyUsages(cert *x509.Certificate) []string {
	var out []string
	ku := cert.KeyUsage
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "DigitalSignature")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "CRLSign")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "KeyAgreement")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "ContentCommitment")
	}
	return out
}

func certExtKeyUsages(cert *x509.Certificate) []string {
	var out []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		}
	}
	return out
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
