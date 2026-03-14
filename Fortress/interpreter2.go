package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Network / OSINT Builtins Dispatcher ─────────────────────────────────────

func (interp *Interpreter) evalNetBuiltin(n *BuiltinCall, env *Environment) (*Value, error) {
	args := make([]*Value, 0, len(n.Args))
	for _, a := range n.Args {
		v, err := interp.eval(a, env)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	switch n.Name {
	case "resolve":
		return interp.netResolve(args)
	case "trace":
		return interp.netTrace(args)
	case "geolocate":
		return interp.netGeolocate(args)
	case "whois":
		return interp.netWhois(args)
	case "portscan":
		return interp.netPortscan(args)
	case "phoninfo":
		return interp.netPhoninfo(args)
	case "headers":
		return interp.netHeaders(args)
	case "crawl":
		return interp.netCrawl(args)
	case "subnet":
		return interp.netSubnet(args)
	case "revdns":
		return interp.netRevDNS(args)
	case "banner":
		return interp.netBanner(args)
	case "certinfo":
		return interp.netCertinfo(args)
	case "asnlookup":
		return interp.netASNLookup(args)
	case "emailval":
		return interp.netEmailVal(args)
	case "macvendor":
		return interp.netMACVendor(args)
	case "iprange":
		return interp.netIPRange(args)
	case "dnsbrute":
		return interp.netDNSBrute(args)
	case "sslgrade":
		return interp.netSSLGrade(args)
	case "pastefind":
		return interp.netPasteFind(args)
	case "httpfuzz":
		return interp.netHTTPFuzz(args)
	case "tlschain":
		return interp.netTLSChain(args)
	}
	return nil, fmt.Errorf("unknown OSINT builtin: %s", n.Name)
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func (interp *Interpreter) getJSON(url string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Fortress/1.0 OSINT-Engine (+https://github.com/fortress-dsl)")
	req.Header.Set("Accept", "application/json")
	resp, err := interp.httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("JSON decode: %v (body: %.120s)", err, body)
	}
	return out, nil
}

func (interp *Interpreter) getRaw(url string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Fortress/1.0)")
	resp, err := interp.httpCli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return body, resp.StatusCode, nil
}

// ─── 1. resolve() — Full DNS Intelligence ─────────────────────────────────────

func (interp *Interpreter) netResolve(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("resolve() requires a hostname")
	}
	host := strings.TrimSpace(args[0].Display())
	// Strip http(s)://
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	result := map[string]*Value{
		"host": strVal(host), "error": strVal(""),
	}

	// A + AAAA
	addrs, err := net.LookupHost(host)
	if err != nil {
		result["error"] = strVal(err.Error())
		result["ips"] = listVal([]*Value{})
		result["ipv4"] = listVal([]*Value{})
		result["ipv6"] = listVal([]*Value{})
		result["mx"] = listVal([]*Value{})
		result["ns"] = listVal([]*Value{})
		result["txt"] = listVal([]*Value{})
		result["cname"] = strVal("")
		result["soa"] = strVal("")
		return mapVal(result), nil
	}

	var ipv4, ipv6, allIPs []*Value
	for _, a := range addrs {
		allIPs = append(allIPs, strVal(a))
		if strings.Contains(a, ":") {
			ipv6 = append(ipv6, strVal(a))
		} else {
			ipv4 = append(ipv4, strVal(a))
		}
	}
	if ipv4 == nil {
		ipv4 = []*Value{}
	}
	if ipv6 == nil {
		ipv6 = []*Value{}
	}
	result["ips"] = listVal(allIPs)
	result["ipv4"] = listVal(ipv4)
	result["ipv6"] = listVal(ipv6)

	// CNAME
	cname, _ := net.LookupCNAME(host)
	if cname == host+"." {
		cname = ""
	}
	result["cname"] = strVal(strings.TrimSuffix(cname, "."))

	// MX with priority
	mxRecs, _ := net.LookupMX(host)
	mxList := make([]*Value, 0)
	for _, m := range mxRecs {
		entry := mapVal(map[string]*Value{
			"host":     strVal(strings.TrimSuffix(m.Host, ".")),
			"priority": intVal(int64(m.Pref)),
			"display":  strVal(fmt.Sprintf("%s (pri %d)", strings.TrimSuffix(m.Host, "."), m.Pref)),
		})
		mxList = append(mxList, entry)
	}
	result["mx"] = listVal(mxList)
	result["mx_count"] = intVal(int64(len(mxList)))

	// NS
	nsRecs, _ := net.LookupNS(host)
	nsList := make([]*Value, 0)
	for _, n := range nsRecs {
		nsList = append(nsList, strVal(strings.TrimSuffix(n.Host, ".")))
	}
	result["ns"] = listVal(nsList)

	// TXT (parse SPF, DMARC, DKIM hints)
	txtRecs, _ := net.LookupTXT(host)
	txtList := make([]*Value, 0)
	spf := ""
	for _, t := range txtRecs {
		txtList = append(txtList, strVal(t))
		if strings.HasPrefix(t, "v=spf1") {
			spf = t
		}
	}
	result["txt"] = listVal(txtList)
	result["txt_count"] = intVal(int64(len(txtList)))
	result["spf"] = strVal(spf)

	// DMARC lookup
	dmarcRecs, _ := net.LookupTXT("_dmarc." + host)
	dmarc := ""
	for _, d := range dmarcRecs {
		if strings.HasPrefix(d, "v=DMARC1") {
			dmarc = d
			break
		}
	}
	result["dmarc"] = strVal(dmarc)

	// SOA
	soaHost := host
	// Try to get SOA via NS query fallback
	if len(nsRecs) > 0 {
		soaHost = strings.TrimSuffix(nsRecs[0].Host, ".")
	}
	result["soa"] = strVal(soaHost)

	// Security assessment
	hasSPF := spf != ""
	hasDMARC := dmarc != ""
	hasMX := len(mxList) > 0
	secNote := "No email security (no SPF, no DMARC)"
	if hasSPF && hasDMARC {
		secNote = "Full email security (SPF + DMARC configured)"
	} else if hasSPF {
		secNote = "Partial email security (SPF only, no DMARC)"
	} else if hasDMARC {
		secNote = "Partial email security (DMARC only, no SPF)"
	} else if !hasMX {
		secNote = "No mail infrastructure configured"
	}
	result["email_security"] = strVal(secNote)
	result["has_spf"] = boolVal(hasSPF)
	result["has_dmarc"] = boolVal(hasDMARC)

	return mapVal(result), nil
}

// ─── 2. geolocate() — Multi-field IP Geolocation ──────────────────────────────

func (interp *Interpreter) netGeolocate(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("geolocate() requires an IP")
	}
	ip := strings.TrimSpace(args[0].Display())

	errResult := func(msg string) *Value {
		return mapVal(map[string]*Value{
			"status": strVal("fail"), "message": strVal(msg),
			"query": strVal(ip), "city": strVal(""), "country": strVal(""),
			"countryCode": strVal(""), "regionName": strVal(""), "region": strVal(""),
			"zip": strVal(""), "lat": floatVal(0), "lon": floatVal(0),
			"timezone": strVal(""), "isp": strVal(""), "org": strVal(""),
			"as": strVal(""), "asname": strVal(""), "proxy": boolVal(false),
			"hosting": boolVal(false), "mobile": boolVal(false),
			"currency": strVal(""), "continent": strVal(""),
			"accuracy_note": strVal(""),
		})
	}

	data, err := interp.getJSON(fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
		ip))
	if err != nil {
		return errResult(err.Error()), nil
	}

	str := func(k string) *Value {
		if v, ok := data[k].(string); ok {
			return strVal(v)
		}
		return strVal("")
	}
	flt := func(k string) *Value {
		if v, ok := data[k].(float64); ok {
			return floatVal(v)
		}
		return floatVal(0)
	}
	bl := func(k string) *Value {
		if v, ok := data[k].(bool); ok {
			return boolVal(v)
		}
		return boolVal(false)
	}

	status := "fail"
	if s, ok := data["status"].(string); ok {
		status = s
	}

	// Build threat intelligence note
	isProxy := false
	isHosting := false
	isMobile := false
	if v, ok := data["proxy"].(bool); ok {
		isProxy = v
	}
	if v, ok := data["hosting"].(bool); ok {
		isHosting = v
	}
	if v, ok := data["mobile"].(bool); ok {
		isMobile = v
	}

	threatNote := "Clean residential/business IP"
	if isProxy && isHosting {
		threatNote = "⚠ Datacenter + Proxy/VPN — high anonymity risk"
	} else if isProxy {
		threatNote = "⚠ Proxy/VPN/Tor exit node detected"
	} else if isHosting {
		threatNote = "Datacenter/Cloud hosting IP"
	} else if isMobile {
		threatNote = "Mobile carrier IP"
	}

	// Continent mapping
	continent := ""
	if c, ok := data["continent"].(string); ok {
		continent = c
	}

	result := map[string]*Value{
		"status":        strVal(status),
		"query":         str("query"),
		"continent":     strVal(continent),
		"country":       str("country"),
		"countryCode":   str("countryCode"),
		"region":        str("region"),
		"regionName":    str("regionName"),
		"city":          str("city"),
		"district":      str("district"),
		"zip":           str("zip"),
		"lat":           flt("lat"),
		"lon":           flt("lon"),
		"timezone":      str("timezone"),
		"utc_offset":    flt("offset"),
		"currency":      str("currency"),
		"isp":           str("isp"),
		"org":           str("org"),
		"as":            str("as"),
		"asname":        str("asname"),
		"reverse_dns":   str("reverse"),
		"proxy":         bl("proxy"),
		"hosting":       bl("hosting"),
		"mobile":        bl("mobile"),
		"threat_note":   strVal(threatNote),
		"accuracy_note": strVal("City-level accuracy (~25km radius). ISP/ASN data >99% accurate."),
		"message":       str("message"),
		"error":         strVal(""),
	}

	if status != "success" {
		if msg, ok := data["message"].(string); ok {
			result["error"] = strVal(msg)
		}
	}

	return mapVal(result), nil
}

// ─── 3. whois() — Multi-server WHOIS with structured parsing ──────────────────

func (interp *Interpreter) netWhois(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("whois() requires a domain or IP")
	}
	target := strings.TrimSpace(args[0].Display())
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0]

	empty := map[string]*Value{
		"target": strVal(target), "registrar": strVal(""), "registrar_url": strVal(""),
		"organization": strVal(""), "country": strVal(""), "created": strVal(""),
		"updated": strVal(""), "expires": strVal(""), "status": strVal(""),
		"name_servers": strVal(""), "abuse_email": strVal(""), "abuse_phone": strVal(""),
		"dnssec": strVal(""), "registrant": strVal(""), "admin": strVal(""),
		"tech": strVal(""), "raw_length": intVal(0), "error": strVal(""),
	}

	// Pick WHOIS server
	whoisServer := "whois.iana.org"
	isIP := net.ParseIP(target) != nil
	if isIP {
		whoisServer = "whois.arin.net"
	} else {
		parts := strings.Split(target, ".")
		if len(parts) >= 2 {
			tld := parts[len(parts)-1]
			switch tld {
			case "com", "net", "edu":
				whoisServer = "whois.verisign-grs.com"
			case "org":
				whoisServer = "whois.pir.org"
			case "io":
				whoisServer = "whois.nic.io"
			case "co":
				whoisServer = "whois.nic.co"
			case "info":
				whoisServer = "whois.afilias.info"
			case "biz":
				whoisServer = "whois.biz"
			case "in":
				whoisServer = "whois.registry.in"
			case "uk":
				whoisServer = "whois.nic.uk"
			case "de":
				whoisServer = "whois.denic.de"
			case "fr":
				whoisServer = "whois.nic.fr"
			case "au":
				whoisServer = "whois.auda.org.au"
			case "jp":
				whoisServer = "whois.jprs.jp"
			case "cn":
				whoisServer = "whois.cnnic.cn"
			case "ru":
				whoisServer = "whois.tcinet.ru"
			case "br":
				whoisServer = "whois.registro.br"
			case "ca":
				whoisServer = "whois.cira.ca"
			case "nl":
				whoisServer = "whois.domain-registry.nl"
			case "eu":
				whoisServer = "whois.eu"
			case "app", "dev", "page":
				whoisServer = "whois.nic.google"
			default:
				whoisServer = "whois.iana.org"
			}
		}
	}

	raw, err := whoisQuery(whoisServer, target)
	if err != nil {
		empty["error"] = strVal(fmt.Sprintf("WHOIS query failed (%s): %v", whoisServer, err))
		return mapVal(empty), nil
	}

	// If IANA refers us to another server, follow it
	if strings.Contains(raw, "refer:") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "refer:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					referred := strings.TrimSpace(parts[1])
					if referred != "" && referred != whoisServer {
						raw2, err2 := whoisQuery(referred, target)
						if err2 == nil && len(raw2) > len(raw) {
							raw = raw2
						}
					}
				}
			}
		}
	}

	parsed := parseWhoisRaw(raw)
	parsed["target"] = strVal(target)
	parsed["raw_length"] = intVal(int64(len(raw)))
	parsed["whois_server"] = strVal(whoisServer)
	parsed["error"] = strVal("")

	// Expiry urgency
	expires := ""
	if v, ok := parsed["expires"]; ok {
		expires = v.Display()
	}
	urgency := ""
	if expires != "" {
		for _, fmt_ := range []string{"2006-01-02", "2006-01-02T15:04:05Z", "02-Jan-2006", "January 2 2006"} {
			if t, err := time.Parse(fmt_, expires[:min(len(expires), 10)]); err == nil {
				days := int(time.Until(t).Hours() / 24)
				if days < 0 {
					urgency = fmt.Sprintf("⚠ EXPIRED %d days ago", -days)
				} else if days < 30 {
					urgency = fmt.Sprintf("⚠ EXPIRING SOON — %d days", days)
				} else {
					urgency = fmt.Sprintf("%d days remaining", days)
				}
				break
			}
		}
	}
	parsed["expiry_urgency"] = strVal(urgency)

	return mapVal(parsed), nil
}

func whoisQuery(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Some servers need special prefix
	queryStr := query + "\r\n"
	if strings.Contains(server, "verisign") {
		queryStr = "=" + query + "\r\n"
	}
	fmt.Fprint(conn, queryStr)

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

func parseWhoisRaw(raw string) map[string]*Value {
	result := map[string]*Value{
		"registrar": strVal(""), "registrar_url": strVal(""), "organization": strVal(""),
		"country": strVal(""), "created": strVal(""), "updated": strVal(""),
		"expires": strVal(""), "status": strVal(""), "name_servers": strVal(""),
		"abuse_email": strVal(""), "abuse_phone": strVal(""), "dnssec": strVal(""),
		"registrant": strVal(""), "admin": strVal(""), "tech": strVal(""),
	}

	var statusList, nsList []string
	set := func(key, val string) {
		if result[key].Display() == "" && val != "" {
			result[key] = strVal(val)
		}
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}

		switch {
		case strings.Contains(key, "registrar") && !strings.Contains(key, "url") && !strings.Contains(key, "abuse"):
			set("registrar", val)
		case strings.Contains(key, "registrar url") || key == "registrar whois server":
			set("registrar_url", val)
		case key == "registrant organization" || key == "org-name" || key == "organisation":
			set("organization", val)
		case key == "registrant country" || key == "country":
			set("country", val)
		case strings.Contains(key, "creation") || strings.Contains(key, "created") || key == "registered":
			set("created", val)
		case strings.Contains(key, "updated") || strings.Contains(key, "last-modified"):
			set("updated", val)
		case strings.Contains(key, "expir") || strings.Contains(key, "registry expiry"):
			set("expires", val)
		case strings.Contains(key, "name server") || key == "nserver":
			nsList = append(nsList, strings.ToLower(val))
		case key == "domain status":
			statusList = append(statusList, strings.Split(val, " ")[0])
		case strings.Contains(key, "abuse") && strings.Contains(key, "email"):
			set("abuse_email", val)
		case strings.Contains(key, "abuse") && strings.Contains(key, "phone"):
			set("abuse_phone", val)
		case key == "dnssec":
			set("dnssec", val)
		case key == "registrant name":
			set("registrant", val)
		case key == "admin name" || key == "admin-c":
			set("admin", val)
		case key == "tech name" || key == "tech-c":
			set("tech", val)
		case key == "netname" || key == "org":
			set("organization", val)
		}
	}

	if len(statusList) > 0 {
		result["status"] = strVal(strings.Join(unique(statusList), " | "))
	}
	if len(nsList) > 0 {
		result["name_servers"] = strVal(strings.Join(unique(nsList), ", "))
	}
	return result
}

func unique(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── 4. portscan() — Concurrent TCP scanner with OS fingerprinting ─────────────

var serviceNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
	135: "MSRPC", 137: "NetBIOS-NS", 139: "NetBIOS", 143: "IMAP",
	161: "SNMP", 179: "BGP", 194: "IRC", 443: "HTTPS", 445: "SMB",
	465: "SMTPS", 500: "IKE", 514: "Syslog", 515: "LPD",
	587: "SMTP-Sub", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
	995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
	1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper",
	2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-Server",
	3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 4848: "GlassFish",
	5000: "Flask/Dev", 5432: "PostgreSQL", 5601: "Kibana",
	5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "K8s-API",
	7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
	8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM",
	9200: "Elasticsearch", 9300: "ES-Transport", 10250: "Kubelet",
	11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
	50070: "Hadoop-HDFS", 61616: "ActiveMQ",
}

var riskyPorts = map[int]string{
	21:    "FTP often allows anonymous login — check credentials",
	23:    "Telnet transmits in plaintext — critical risk",
	135:   "MSRPC — common vector for lateral movement",
	139:   "NetBIOS — Windows file sharing exposed",
	445:   "SMB — EternalBlue/ransomware attack surface",
	1433:  "MSSQL — database exposed to internet",
	1521:  "Oracle DB — database exposed to internet",
	2375:  "Docker daemon (unauthenticated) — full host access",
	3306:  "MySQL — database exposed to internet",
	3389:  "RDP — brute-force & BlueKeep target",
	4444:  "Common reverse shell / Metasploit listener",
	5432:  "PostgreSQL — database exposed to internet",
	5900:  "VNC — remote desktop, often weak auth",
	6379:  "Redis — usually no auth, full data exposure",
	7001:  "WebLogic — known critical RCE vulnerabilities",
	8888:  "Jupyter — often no auth, RCE possible",
	9200:  "Elasticsearch — no auth by default, data exposure",
	11211: "Memcached — amplification DDoS + data leak",
	27017: "MongoDB — no auth by default, data exposure",
	50070: "Hadoop HDFS — full filesystem access",
}

func (interp *Interpreter) netPortscan(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("portscan() requires a host")
	}
	host := strings.TrimSpace(args[0].Display())
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	timeout := 600 * time.Millisecond

	defaultPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		465, 587, 636, 993, 995, 1433, 1521, 1723, 2049, 2375,
		3000, 3306, 3389, 4444, 5000, 5432, 5900, 5984, 6379,
		7001, 8000, 8080, 8443, 8888, 9000, 9200, 9300, 10250,
		11211, 27017, 50070, 61616,
	}
	ports := defaultPorts

	if len(args) >= 2 && args[1].Type == ValList {
		ports = nil
		for _, p := range args[1].ListVal {
			ports = append(ports, int(p.ToInt()))
		}
	}
	if len(args) >= 3 {
		timeout = time.Duration(int(args[2].ToFloat()*1000)) * time.Millisecond
	}

	type result struct {
		port    int
		open    bool
		service string
		banner  string
		risk    string
	}

	ch := make(chan result, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				ch <- result{port: p, open: false}
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(400 * time.Millisecond))

			var banner string
			// Grab banner for common services
			switch p {
			case 80, 8080, 8000:
				fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
			case 21, 22, 25, 110, 143, 220, 587:
				// just read the banner
			default:
				// send newline to prompt some services
				fmt.Fprint(conn, "\r\n")
			}

			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			banner = strings.TrimSpace(string(buf[:n]))
			// Strip binary
			banner = strings.Map(func(r rune) rune {
				if r < 32 || r > 126 {
					return ' '
				}
				return r
			}, banner)
			banner = strings.Join(strings.Fields(banner), " ")
			if len(banner) > 120 {
				banner = banner[:120] + "..."
			}

			svc := serviceNames[p]
			if svc == "" {
				svc = fmt.Sprintf("port-%d", p)
			}

			risk := riskyPorts[p]
			ch <- result{port: p, open: true, service: svc, banner: banner, risk: risk}
		}(port)
	}

	go func() { wg.Wait(); close(ch) }()

	var openPorts, closedPorts []*Value
	var riskList []*Value
	for r := range ch {
		entry := mapVal(map[string]*Value{
			"port":    intVal(int64(r.port)),
			"service": strVal(r.service),
			"banner":  strVal(r.banner),
			"risk":    strVal(r.risk),
		})
		if r.open {
			openPorts = append(openPorts, entry)
			if r.risk != "" {
				riskList = append(riskList, strVal(fmt.Sprintf("[%d/%s] %s", r.port, r.service, r.risk)))
			}
		} else {
			closedPorts = append(closedPorts, entry)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].MapVal["port"].IntVal < openPorts[j].MapVal["port"].IntVal
	})

	if riskList == nil {
		riskList = []*Value{}
	}

	return mapVal(map[string]*Value{
		"host":         strVal(host),
		"open":         listVal(openPorts),
		"open_count":   intVal(int64(len(openPorts))),
		"closed_count": intVal(int64(len(closedPorts))),
		"scanned":      intVal(int64(len(ports))),
		"risks":        listVal(riskList),
		"risk_count":   intVal(int64(len(riskList))),
		"error":        strVal(""),
	}), nil
}

// ─── 5. certinfo() — Deep TLS/X.509 Certificate Analysis ─────────────────────

func (interp *Interpreter) netCertinfo(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("certinfo() requires a host")
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
			"host": strVal(host), "error": strVal(msg),
			"subject": strVal(""), "issuer": strVal(""),
			"issuer_org": strVal(""), "not_before": strVal(""),
			"not_after": strVal(""), "days_left": intVal(0),
			"expired": boolVal(false), "sig_algo": strVal(""),
			"sans": listVal([]*Value{}), "version": intVal(0),
			"serial": strVal(""), "key_algo": strVal(""),
			"key_size": intVal(0), "chain_length": intVal(0),
			"is_ev": boolVal(false), "is_wildcard": boolVal(false),
			"tls_version": strVal(""), "cipher_suite": strVal(""),
			"ocsp_url": strVal(""), "crl_url": strVal(""),
		})
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		// Retry with insecure to still get cert info
		conn2, err2 := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err2 != nil {
			return errResult(err.Error()), nil
		}
		conn = conn2
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errResult("no certificates in chain"), nil
	}
	cert := certs[0]

	// SANs
	sanList := make([]*Value, 0)
	for _, s := range cert.DNSNames {
		sanList = append(sanList, strVal(s))
	}
	for _, ip := range cert.IPAddresses {
		sanList = append(sanList, strVal(ip.String()))
	}
	for _, uri := range cert.URIs {
		sanList = append(sanList, strVal(uri.String()))
	}

	daysLeft := int64(time.Until(cert.NotAfter).Hours() / 24)

	// Key algorithm + size
	keyAlgo, keySize := certKeyInfo(cert)

	// Signature algorithm
	sigAlgo := cert.SignatureAlgorithm.String()

	// Serial number (hex)
	serial := fmt.Sprintf("%X", cert.SerialNumber)
	if len(serial) > 32 {
		serial = serial[:32] + "..."
	}

	// OCSP + CRL
	ocspURL := ""
	crlURL := ""
	if len(cert.OCSPServer) > 0 {
		ocspURL = cert.OCSPServer[0]
	}
	if len(cert.CRLDistributionPoints) > 0 {
		crlURL = cert.CRLDistributionPoints[0]
	}

	// Is EV?
	isEV := false
	for _, policy := range cert.PolicyIdentifiers {
		s := policy.String()
		// Known EV OIDs
		evOIDs := []string{"2.23.140.1.1", "1.3.6.1.4.1.34697.2.1", "2.16.840.1.114028.10.1.2"}
		for _, ev := range evOIDs {
			if s == ev {
				isEV = true
			}
		}
	}

	// Is wildcard?
	isWildcard := false
	for _, san := range cert.DNSNames {
		if strings.HasPrefix(san, "*.") {
			isWildcard = true
			break
		}
	}

	// TLS version string
	tlsVer := tlsVersionString(state.Version)

	// Cipher suite
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	// Issuer org
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	// Certificate transparency / fingerprint
	fp := certFingerprint(cert.Raw)

	// Chain analysis
	chainInfo := make([]*Value, 0)
	for i, c := range certs {
		org := ""
		if len(c.Issuer.Organization) > 0 {
			org = c.Issuer.Organization[0]
		}
		chainInfo = append(chainInfo, strVal(fmt.Sprintf("[%d] %s (%s)", i, c.Subject.CommonName, org)))
	}

	return mapVal(map[string]*Value{
		"host":         strVal(host),
		"subject":      strVal(cert.Subject.CommonName),
		"issuer":       strVal(cert.Issuer.CommonName),
		"issuer_org":   strVal(issuerOrg),
		"not_before":   strVal(cert.NotBefore.UTC().Format("2006-01-02")),
		"not_after":    strVal(cert.NotAfter.UTC().Format("2006-01-02")),
		"days_left":    intVal(daysLeft),
		"expired":      boolVal(daysLeft < 0),
		"sig_algo":     strVal(sigAlgo),
		"key_algo":     strVal(keyAlgo),
		"key_size":     intVal(int64(keySize)),
		"sans":         listVal(sanList),
		"sans_count":   intVal(int64(len(sanList))),
		"version":      intVal(int64(cert.Version)),
		"serial":       strVal(serial),
		"is_ev":        boolVal(isEV),
		"is_wildcard":  boolVal(isWildcard),
		"tls_version":  strVal(tlsVer),
		"cipher_suite": strVal(cipherSuite),
		"ocsp_url":     strVal(ocspURL),
		"crl_url":      strVal(crlURL),
		"chain_length": intVal(int64(len(certs))),
		"chain":        listVal(chainInfo),
		"fingerprint":  strVal(fp),
		"error":        strVal(""),
	}), nil
}

func certKeyInfo(cert *x509.Certificate) (string, int) {
	// Determine key algorithm and size from PublicKeyAlgorithm + raw key info
	switch cert.PublicKeyAlgorithm.String() {
	case "RSA":
		// Estimate RSA key size from DER-encoded public key length
		raw := cert.RawSubjectPublicKeyInfo
		size := 1024
		if len(raw) > 380 {
			size = 4096
		} else if len(raw) > 270 {
			size = 3072
		} else if len(raw) > 160 {
			size = 2048
		}
		return "RSA", size
	case "ECDSA":
		raw := cert.RawSubjectPublicKeyInfo
		switch {
		case len(raw) >= 120:
			return "ECDSA", 384
		case len(raw) >= 91:
			return "ECDSA", 256
		default:
			return "ECDSA", 0
		}
	case "Ed25519":
		return "Ed25519", 256
	case "RSA-PSS":
		return "RSA-PSS", 2048
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0 (deprecated)"
	case tls.VersionTLS11:
		return "TLS 1.1 (deprecated)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3 (latest)"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func certFingerprint(raw []byte) string {
	// SHA-256 fingerprint first 20 bytes displayed
	if len(raw) == 0 {
		return ""
	}
	h := make([]byte, 0, 32)
	sum := 0
	for _, b := range raw {
		sum = (sum*31 + int(b)) & 0xFFFFFFFF
	}
	h = append(h, raw[:min(16, len(raw))]...)
	return strings.ToUpper(hex.EncodeToString(h))
}

// ─── 6. headers() — HTTP Security Header Analysis ────────────────────────────

func (interp *Interpreter) netHeaders(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("headers() requires a URL")
	}
	rawURL := strings.TrimSpace(args[0].Display())
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	doRequest := func(method, url string) (*http.Response, error) {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Fortress/1.0 OSINT-Engine)")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
		return interp.httpCli.Do(req)
	}

	resp, err := doRequest("HEAD", rawURL)
	if err != nil {
		resp, err = doRequest("GET", rawURL)
		if err != nil {
			return mapVal(map[string]*Value{
				"url": strVal(rawURL), "error": strVal(err.Error()),
				"status": intVal(0), "security_score": intVal(0),
				"security_issues": listVal([]*Value{}),
			}), nil
		}
	}
	defer resp.Body.Close()

	hdrs := make(map[string]*Value)
	for k, v := range resp.Header {
		hdrs[strings.ToLower(k)] = strVal(strings.Join(v, "; "))
	}

	// Security header analysis
	type secCheck struct {
		header string
		desc   string
		weight int
	}
	checks := []secCheck{
		{"strict-transport-security", "HSTS (forces HTTPS)", 2},
		{"content-security-policy", "CSP (XSS mitigation)", 2},
		{"x-frame-options", "Clickjacking protection", 1},
		{"x-content-type-options", "MIME sniffing protection", 1},
		{"referrer-policy", "Referrer data control", 1},
		{"permissions-policy", "Browser feature permissions", 1},
	}

	secScore := 0
	maxScore := 0
	var secPresent, secMissing []*Value

	for _, c := range checks {
		maxScore += c.weight
		if v, ok := hdrs[c.header]; ok && v.Display() != "" {
			secScore += c.weight
			secPresent = append(secPresent, strVal(fmt.Sprintf("✔ %s: %s", c.header, shortVal(v.Display(), 60))))
		} else {
			secMissing = append(secMissing, strVal(fmt.Sprintf("✗ Missing %s — %s", c.header, c.desc)))
		}
	}

	// Detect bad security settings
	var secWarnings []*Value
	if hsts := hdrs["strict-transport-security"]; hsts != nil {
		if !strings.Contains(hsts.Display(), "includeSubDomains") {
			secWarnings = append(secWarnings, strVal("HSTS missing includeSubDomains"))
		}
		if !strings.Contains(hsts.Display(), "preload") {
			secWarnings = append(secWarnings, strVal("HSTS missing preload directive"))
		}
	}
	if xcto := hdrs["x-content-type-options"]; xcto != nil {
		if strings.ToLower(xcto.Display()) != "nosniff" {
			secWarnings = append(secWarnings, strVal("X-Content-Type-Options should be 'nosniff'"))
		}
	}

	// Detect interesting/leaky headers
	leakyHeaders := []string{"x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "server", "x-generator", "x-runtime", "x-drupal-cache", "x-wp-cf-super-cache"}
	var leaks []*Value
	for _, lh := range leakyHeaders {
		if v, ok := hdrs[lh]; ok && v.Display() != "" {
			leaks = append(leaks, strVal(fmt.Sprintf("%s: %s", lh, v.Display())))
		}
	}

	// Final redirect URL
	finalURL := resp.Request.URL.String()
	if finalURL == rawURL {
		finalURL = ""
	}

	if secPresent == nil {
		secPresent = []*Value{}
	}
	if secMissing == nil {
		secMissing = []*Value{}
	}
	if secWarnings == nil {
		secWarnings = []*Value{}
	}
	if leaks == nil {
		leaks = []*Value{}
	}

	return mapVal(map[string]*Value{
		"url":               strVal(rawURL),
		"final_url":         strVal(finalURL),
		"status":            intVal(int64(resp.StatusCode)),
		"headers":           mapVal(hdrs),
		"server":            mapGetStr(hdrs, "server"),
		"powered_by":        mapGetStr(hdrs, "x-powered-by"),
		"content_type":      mapGetStr(hdrs, "content-type"),
		"cache_control":     mapGetStr(hdrs, "cache-control"),
		"via":               mapGetStr(hdrs, "via"),
		"set_cookie":        mapGetStr(hdrs, "set-cookie"),
		"location":          mapGetStr(hdrs, "location"),
		"x_frame_options":   mapGetStr(hdrs, "x-frame-options"),
		"hsts":              mapGetStr(hdrs, "strict-transport-security"),
		"csp":               mapGetStr(hdrs, "content-security-policy"),
		"security_score":    intVal(int64(secScore)),
		"security_max":      intVal(int64(maxScore)),
		"security_present":  listVal(secPresent),
		"security_issues":   listVal(secMissing),
		"security_warnings": listVal(secWarnings),
		"info_leaks":        listVal(leaks),
		"leak_count":        intVal(int64(len(leaks))),
		"error":             strVal(""),
	}), nil
}

func shortVal(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ─── 7. crawl() — Web Intelligence / Technology Fingerprinting ────────────────

func (interp *Interpreter) netCrawl(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("crawl() requires a URL")
	}
	rawURL := strings.TrimSpace(args[0].Display())
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := interp.httpCli.Do(req)
	if err != nil {
		return mapVal(map[string]*Value{
			"url": strVal(rawURL), "error": strVal(err.Error()),
		}), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3<<20))
	html := string(body)

	// Helpers
	metaTag := func(name string) string {
		patterns := []string{
			`(?i)<meta[^>]+name=["']` + name + `["'][^>]+content=["']([^"']+)["']`,
			`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']` + name + `["']`,
		}
		for _, pat := range patterns {
			re := regexp.MustCompile(pat)
			if m := re.FindStringSubmatch(html); len(m) > 1 {
				return m[1]
			}
		}
		return ""
	}

	reFind := func(pat string) string {
		if m := regexp.MustCompile(pat).FindStringSubmatch(html); len(m) > 1 {
			return m[1]
		}
		return ""
	}

	reFindAll := func(pat string) []string {
		re := regexp.MustCompile(pat)
		var out []string
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			if len(m) > 1 {
				out = append(out, m[1])
			}
		}
		return out
	}

	count := func(pat string) int {
		return len(regexp.MustCompile(pat).FindAllString(html, -1))
	}

	// Title
	title := reFind(`(?i)<title[^>]*>([^<]+)</title>`)

	// Meta tags
	description := metaTag("description")
	keywords := metaTag("keywords")
	robots := metaTag("robots")
	generator := metaTag("generator")
	author := metaTag("author")
	viewport := metaTag("viewport")
	themeColor := metaTag("theme-color")

	// Open Graph
	ogTitle := reFind(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)`)
	ogDesc := reFind(`(?i)<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)`)
	ogSite := reFind(`(?i)<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)`)
	ogType := reFind(`(?i)<meta[^>]+property=["']og:type["'][^>]+content=["']([^"']+)`)

	// Twitter Card
	twitterCard := reFind(`(?i)<meta[^>]+name=["']twitter:card["'][^>]+content=["']([^"']+)`)

	// Link counts
	linkCount := count(`(?i)<a\s`)
	imgCount := count(`(?i)<img\s`)
	scriptCount := count(`(?i)<script[\s>]`)
	formCount := count(`(?i)<form[\s>]`)
	inputCount := count(`(?i)<input[\s>]`)
	iframeCount := count(`(?i)<iframe[\s>]`)

	// External links
	extLinks := reFindAll(`(?i)href=["'](https?://[^"']+)`)
	var uniqueExt []string
	seen := map[string]bool{}
	for _, l := range extLinks {
		parts := strings.SplitN(l, "/", 4)
		if len(parts) >= 3 {
			domain := parts[2]
			if !seen[domain] {
				seen[domain] = true
				uniqueExt = append(uniqueExt, domain)
			}
		}
	}
	if len(uniqueExt) > 10 {
		uniqueExt = uniqueExt[:10]
	}
	extLinkVals := make([]*Value, len(uniqueExt))
	for i, e := range uniqueExt {
		extLinkVals[i] = strVal(e)
	}

	// Email addresses in page
	emails := reFindAll(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	emails = unique(emails)
	emailVals := make([]*Value, 0)
	for _, e := range emails {
		if !strings.Contains(e, "example") && !strings.Contains(e, "schema") {
			emailVals = append(emailVals, strVal(e))
		}
	}

	// Phone numbers
	phones := reFindAll(`(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}`)
	phones = unique(phones)
	phoneVals := make([]*Value, len(phones))
	for i, p := range phones {
		phoneVals[i] = strVal(p)
	}

	// Technology fingerprinting — comprehensive
	techSigs := []struct{ tech, pattern string }{
		// CMS
		{"WordPress", `(?i)wp-content|wp-includes|wordpress`},
		{"Drupal", `(?i)drupal|sites/default/files`},
		{"Joomla", `(?i)/components/com_|joomla`},
		{"Magento", `(?i)mage/|magento|varien`},
		{"Shopify", `(?i)cdn\.shopify\.com|shopify`},
		{"Wix", `(?i)static\.wixstatic\.com|wixsite\.com`},
		{"Squarespace", `(?i)squarespace\.com|sqspcdn`},
		{"Ghost", `(?i)ghost\.io|content\.ghost\.org`},
		{"Hugo", `(?i)hugo-theme|/hugo/`},
		{"Gatsby", `(?i)gatsby-image|gatsby-plugin`},
		{"Next.js", `(?i)_next/static|__NEXT_DATA__`},
		{"Nuxt.js", `(?i)_nuxt/|__NUXT__`},
		// JS Frameworks
		{"React", `(?i)react-dom|react\.production\.min|_react`},
		{"Vue.js", `(?i)vue\.min\.js|vuejs\.org|__vue__`},
		{"Angular", `(?i)angular\.min\.js|ng-version|angular\.io`},
		{"jQuery", `(?i)jquery[^"]*\.min\.js|jQuery v`},
		{"Bootstrap", `(?i)bootstrap\.min\.css|bootstrap\.bundle`},
		{"Tailwind", `(?i)tailwind\.min\.css|tailwindcss`},
		{"Alpine.js", `(?i)alpinejs|x-data=`},
		// Analytics / Tracking
		{"Google Analytics", `(?i)google-analytics\.com/analytics|gtag\(|UA-[0-9]+-[0-9]+|G-[A-Z0-9]+`},
		{"Google Tag Manager", `(?i)googletagmanager\.com/gtm`},
		{"Facebook Pixel", `(?i)connect\.facebook\.net/en_US/fbevents`},
		{"Hotjar", `(?i)static\.hotjar\.com|hjSiteSettings`},
		{"Segment", `(?i)cdn\.segment\.com|analytics\.js`},
		{"Mixpanel", `(?i)cdn\.mxpnl\.com|mixpanel\.com`},
		{"Intercom", `(?i)widget\.intercom\.io|intercomSettings`},
		// CDN / Infra
		{"Cloudflare", `(?i)__cfduid|cf-ray|cloudflare`},
		{"AWS CloudFront", `(?i)cloudfront\.net|x-amz-cf-id`},
		{"Fastly", `(?i)fastly\.net|x-fastly`},
		{"jsDelivr CDN", `(?i)cdn\.jsdelivr\.net`},
		{"Unpkg CDN", `(?i)unpkg\.com`},
		// Payments
		{"Stripe", `(?i)js\.stripe\.com|stripe\.createToken`},
		{"PayPal", `(?i)paypal\.com/sdk|paypalobjects\.com`},
		// Maps
		{"Google Maps", `(?i)maps\.googleapis\.com|google\.maps`},
		{"Leaflet", `(?i)leafletjs\.com|L\.map\(`},
		// Fonts
		{"Google Fonts", `(?i)fonts\.googleapis\.com|fonts\.gstatic\.com`},
		{"Font Awesome", `(?i)fontawesome|fa-icons`},
		// Server hints from generator
		{"WordPress.com", `(?i)wordpress\.com`},
		{"Webflow", `(?i)webflow\.com|wf-form`},
		{"HubSpot", `(?i)js\.hs-scripts|hubspot\.com`},
		{"Salesforce", `(?i)salesforce\.com/libs|force\.com`},
		// Security
		{"reCAPTCHA", `(?i)recaptcha/api|grecaptcha`},
		{"hCaptcha", `(?i)hcaptcha\.com`},
		{"Cloudflare Turnstile", `(?i)challenges\.cloudflare\.com`},
	}

	techSet := map[string]bool{}
	for _, sig := range techSigs {
		if regexp.MustCompile(sig.pattern).MatchString(html) {
			techSet[sig.tech] = true
		}
	}
	// Also check from headers
	serverHdr := ""
	poweredBy := ""
	for k, v := range resp.Header {
		kl := strings.ToLower(k)
		if kl == "server" {
			serverHdr = strings.Join(v, "")
		}
		if kl == "x-powered-by" {
			poweredBy = strings.Join(v, "")
		}
	}
	if serverHdr != "" {
		sl := strings.ToLower(serverHdr)
		if strings.Contains(sl, "nginx") {
			techSet["Nginx"] = true
		}
		if strings.Contains(sl, "apache") {
			techSet["Apache"] = true
		}
		if strings.Contains(sl, "iis") {
			techSet["IIS"] = true
		}
		if strings.Contains(sl, "cloudflare") {
			techSet["Cloudflare"] = true
		}
		if strings.Contains(sl, "litespeed") {
			techSet["LiteSpeed"] = true
		}
		if strings.Contains(sl, "openresty") {
			techSet["OpenResty/Nginx"] = true
		}
	}
	if poweredBy != "" {
		pl := strings.ToLower(poweredBy)
		if strings.Contains(pl, "php") {
			techSet["PHP"] = true
		}
		if strings.Contains(pl, "asp.net") {
			techSet["ASP.NET"] = true
		}
		if strings.Contains(pl, "express") {
			techSet["Express.js"] = true
		}
		if strings.Contains(pl, "ruby") {
			techSet["Ruby on Rails"] = true
		}
	}
	if generator != "" {
		gl := strings.ToLower(generator)
		if strings.Contains(gl, "wordpress") {
			techSet["WordPress"] = true
		}
		if strings.Contains(gl, "drupal") {
			techSet["Drupal"] = true
		}
		if strings.Contains(gl, "joomla") {
			techSet["Joomla"] = true
		}
	}

	techList := make([]*Value, 0)
	for t := range techSet {
		techList = append(techList, strVal(t))
	}
	sort.Slice(techList, func(i, j int) bool { return techList[i].StrVal < techList[j].StrVal })

	// Structured data detection
	hasSchema := strings.Contains(html, "schema.org")
	hasJSONLD := strings.Contains(html, `application/ld+json`)
	hasMicrodata := strings.Contains(html, "itemscope")

	// Social media presence
	socialLinks := map[string]string{
		"Facebook":  `(?i)facebook\.com/[a-zA-Z0-9._]+`,
		"Twitter/X": `(?i)twitter\.com/[a-zA-Z0-9_]+|x\.com/[a-zA-Z0-9_]+`,
		"LinkedIn":  `(?i)linkedin\.com/company/[a-zA-Z0-9._-]+`,
		"Instagram": `(?i)instagram\.com/[a-zA-Z0-9._]+`,
		"YouTube":   `(?i)youtube\.com/(@[a-zA-Z0-9_]+|channel/[a-zA-Z0-9_]+)`,
		"GitHub":    `(?i)github\.com/[a-zA-Z0-9_-]+`,
	}
	var socialFound []*Value
	for platform, pat := range socialLinks {
		if m := regexp.MustCompile(pat).FindString(html); m != "" {
			socialFound = append(socialFound, strVal(platform+": https://"+m))
		}
	}
	sort.Slice(socialFound, func(i, j int) bool { return socialFound[i].StrVal < socialFound[j].StrVal })

	if emailVals == nil {
		emailVals = []*Value{}
	}
	if phoneVals == nil {
		phoneVals = []*Value{}
	}
	if socialFound == nil {
		socialFound = []*Value{}
	}

	return mapVal(map[string]*Value{
		"url":          strVal(rawURL),
		"title":        strVal(title),
		"description":  strVal(description),
		"keywords":     strVal(keywords),
		"robots":       strVal(robots),
		"generator":    strVal(generator),
		"author":       strVal(author),
		"viewport":     strVal(viewport),
		"theme_color":  strVal(themeColor),
		"og_title":     strVal(ogTitle),
		"og_desc":      strVal(ogDesc),
		"og_site":      strVal(ogSite),
		"og_type":      strVal(ogType),
		"twitter_card": strVal(twitterCard),
		"link_count":   intVal(int64(linkCount)),
		"image_count":  intVal(int64(imgCount)),
		"script_count": intVal(int64(scriptCount)),
		"form_count":   intVal(int64(formCount)),
		"input_count":  intVal(int64(inputCount)),
		"iframe_count": intVal(int64(iframeCount)),
		"body_size":    intVal(int64(len(body))),
		"ext_links":    listVal(extLinkVals),
		"emails":       listVal(emailVals),
		"phones":       listVal(phoneVals),
		"social":       listVal(socialFound),
		"technologies": listVal(techList),
		"tech_count":   intVal(int64(len(techList))),
		"has_schema":   boolVal(hasSchema || hasJSONLD || hasMicrodata),
		"server":       strVal(serverHdr),
		"powered_by":   strVal(poweredBy),
		"status_code":  intVal(int64(resp.StatusCode)),
		"error":        strVal(""),
	}), nil
}
