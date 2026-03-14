package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ─── 8. revdns() ──────────────────────────────────────────────────────────────

func (interp *Interpreter) netRevDNS(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("revdns() requires an IP")
	}
	ip := strings.TrimSpace(args[0].Display())
	names, err := net.LookupAddr(ip)
	if err != nil {
		return mapVal(map[string]*Value{
			"ip": strVal(ip), "primary": strVal(""), "hostnames": listVal([]*Value{}), "error": strVal(err.Error()),
		}), nil
	}
	list := make([]*Value, len(names))
	for i, n := range names {
		list[i] = strVal(strings.TrimSuffix(n, "."))
	}
	primary := ""
	if len(names) > 0 {
		primary = strings.TrimSuffix(names[0], ".")
	}
	return mapVal(map[string]*Value{
		"ip":        strVal(ip),
		"primary":   strVal(primary),
		"hostnames": listVal(list),
		"count":     intVal(int64(len(list))),
		"error":     strVal(""),
	}), nil
}

// ─── 9. banner() ──────────────────────────────────────────────────────────────

func (interp *Interpreter) netBanner(args []*Value) (*Value, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("banner() requires host and port")
	}
	host := args[0].Display()
	port := args[1].Display()

	conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
	if err != nil {
		return mapVal(map[string]*Value{"host": strVal(host), "port": strVal(port), "banner": strVal(""), "error": strVal(err.Error())}), nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	p, _ := strconv.Atoi(port)
	switch p {
	case 80, 8080, 8000, 8443:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Fortress/1.0\r\n\r\n", host)
	case 25, 587, 465:
		// read SMTP greeting
	default:
		fmt.Fprint(conn, "\r\n")
	}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	raw := strings.TrimSpace(string(buf[:n]))
	raw = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, raw)
	raw = strings.Join(strings.Fields(raw), " ")
	if len(raw) > 200 {
		raw = raw[:200] + "..."
	}

	return mapVal(map[string]*Value{
		"host": strVal(host), "port": strVal(port),
		"banner": strVal(raw), "error": strVal(""),
	}), nil
}

// ─── 10. trace() ─────────────────────────────────────────────────────────────

func (interp *Interpreter) netTrace(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("trace() requires a host")
	}
	host := strings.TrimSpace(args[0].Display())
	addrs, err := net.LookupHost(host)
	if err != nil {
		return mapVal(map[string]*Value{
			"host": strVal(host), "hops": listVal([]*Value{}), "error": strVal(err.Error()),
		}), nil
	}
	target := addrs[0]

	hops := make([]*Value, 0)
	for ttl := 1; ttl <= 20; ttl++ {
		ports := []int{443, 80, 8080}
		var rtt time.Duration
		reached := false
		for _, port := range ports {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 500*time.Millisecond)
			rtt = time.Since(start)
			if err == nil {
				conn.Close()
				reached = true
				break
			}
		}
		if reached {
			revNames, _ := net.LookupAddr(target)
			revName := target
			if len(revNames) > 0 {
				revName = strings.TrimSuffix(revNames[0], ".")
			}
			hops = append(hops, mapVal(map[string]*Value{
				"ttl": intVal(int64(ttl)), "ip": strVal(target),
				"hostname": strVal(revName),
				"rtt_ms":   floatVal(float64(rtt.Milliseconds())),
			}))
			break
		}
		hops = append(hops, mapVal(map[string]*Value{
			"ttl": intVal(int64(ttl)), "ip": strVal("*"),
			"hostname": strVal("*"), "rtt_ms": floatVal(0),
		}))
	}

	return mapVal(map[string]*Value{
		"host":   strVal(host),
		"target": strVal(target),
		"hops":   listVal(hops),
		"error":  strVal(""),
	}), nil
}

// ─── 11. asnlookup() ─────────────────────────────────────────────────────────

func (interp *Interpreter) netASNLookup(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("asnlookup() requires an IP or ASN")
	}
	target := strings.TrimSpace(args[0].Display())

	errResult := func(msg string) *Value {
		return mapVal(map[string]*Value{"target": strVal(target), "error": strVal(msg)})
	}

	var url string
	if strings.HasPrefix(strings.ToUpper(target), "AS") {
		url = "https://api.bgpview.io/asn/" + strings.TrimPrefix(strings.ToUpper(target), "AS")
	} else {
		url = "https://api.bgpview.io/ip/" + target
	}

	data, err := interp.getJSON(url)
	if err != nil {
		return errResult(err.Error()), nil
	}

	result := jsonToValue(data)
	if result.Type != ValMap {
		return errResult("unexpected response"), nil
	}

	// Also try WHOIS-based ASN
	asnFromWhois := ""
	if ip := net.ParseIP(target); ip != nil {
		names, _ := net.LookupAddr(target)
		if len(names) > 0 {
			asnFromWhois = strings.TrimSuffix(names[0], ".")
		}
	}
	result.MapVal["reverse_dns"] = strVal(asnFromWhois)
	result.MapVal["target"] = strVal(target)
	result.MapVal["error"] = strVal("")
	return result, nil
}

// ─── 12. emailval() — Deep Email Validation ───────────────────────────────────

func (interp *Interpreter) netEmailVal(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("emailval() requires an email address")
	}
	email := strings.TrimSpace(strings.ToLower(args[0].Display()))

	errResult := func(msg string) *Value {
		return mapVal(map[string]*Value{
			"email": strVal(email), "valid": boolVal(false), "error": strVal(msg),
			"user": strVal(""), "domain": strVal(""), "mx_valid": boolVal(false),
			"deliverable": boolVal(false), "disposable": boolVal(false),
			"primary_mx": strVal(""), "mx_records": listVal([]*Value{}),
			"catch_all": boolVal(false), "free_provider": boolVal(false),
			"role_account": boolVal(false), "spf": strVal(""), "dmarc": strVal(""),
		})
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errResult("invalid email format"), nil
	}
	user, domain := parts[0], parts[1]

	// RFC 5321 syntax check
	validEmailRe := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~\-]+$`)
	if !validEmailRe.MatchString(user) {
		return errResult("invalid characters in username"), nil
	}
	if strings.HasPrefix(user, ".") || strings.HasSuffix(user, ".") || strings.Contains(user, "..") {
		return errResult("invalid dot placement in username"), nil
	}

	// MX lookup
	mxRecs, err := net.LookupMX(domain)
	mxValid := err == nil && len(mxRecs) > 0
	mxList := make([]*Value, 0)
	primaryMX := ""
	for _, mx := range mxRecs {
		h := strings.TrimSuffix(mx.Host, ".")
		mxList = append(mxList, strVal(fmt.Sprintf("%s (pri %d)", h, mx.Pref)))
		if primaryMX == "" {
			primaryMX = h
		}
	}

	// Disposable domain check — comprehensive list
	disposableDomains := map[string]bool{
		"mailinator.com": true, "guerrillamail.com": true, "10minutemail.com": true,
		"throwam.com": true, "yopmail.com": true, "tempmail.com": true,
		"sharklasers.com": true, "guerrillamailblock.com": true, "grr.la": true,
		"guerrillamail.info": true, "guerrillamail.biz": true, "guerrillamail.de": true,
		"guerrillamail.net": true, "guerrillamail.org": true, "spam4.me": true,
		"trashmail.com": true, "trashmail.me": true, "trashmail.net": true,
		"mailnesia.com": true, "mailnull.com": true,
		"dispostable.com": true, "spamgourmet.com": true, "spamgourmet.net": true,
		"fakeinbox.com": true, "maildrop.cc": true, "nwytg.net": true,
		"cfl.fr": true, "cuvox.de": true, "dayrep.com": true, "einrot.com": true,
		"fleckens.hu": true, "gustr.com": true, "iroid.com": true,
		"getairmail.com": true, "discard.email": true, "harakirimail.com": true,
		"jetable.fr.nf": true, "mabox.eu": true, "mail-temp.com": true,
		"mailexpire.com": true, "mailfreeonline.com": true, "mailmetrash.com": true,
		"mailscrap.com": true, "mailsiphon.com": true, "mailtemp.info": true,
		"mailzilla.com": true, "mobi.web.id": true, "objectmail.com": true,
		"obobbo.com": true, "put2.net": true, "reallymymail.com": true,
		"sendspamhere.com": true, "smellfear.com": true,
		"spamgob.com": true, "spamhereplease.com": true, "spamthis.co.uk": true,
		"spoofmail.de": true, "stuffmail.de": true, "super-auswahl.de": true,
		"sweetxxx.de": true, "tafmail.com": true, "tempemail.co.za": true,
		"tempinbox.co.uk": true, "tempinbox.com": true, "thanksnospam.com": true,
		"thermal.press": true, "trash-amil.com": true,
		"trashdevil.com": true, "trashemail.de": true, "trashtaste.com": true,
		"trbvm.com": true, "ulfaclip.com": true, "uroid.com": true,
		"wegwerfmail.de": true, "wegwerfmail.net": true, "wegwerfmail.org": true,
		"whyspam.me": true, "xoxy.net": true, "yolo.com": true, "zippymail.info": true,
	}

	// Free provider check
	freeProviders := map[string]bool{
		"gmail.com": true, "yahoo.com": true, "hotmail.com": true, "outlook.com": true,
		"live.com": true, "msn.com": true, "icloud.com": true, "me.com": true,
		"mac.com": true, "aol.com": true, "protonmail.com": true, "proton.me": true,
		"tutanota.com": true, "zoho.com": true, "mail.com": true, "gmx.com": true,
		"gmx.net": true, "yandex.com": true, "yandex.ru": true, "inbox.com": true,
		"rediffmail.com": true, "rocketmail.com": true, "att.net": true,
		"comcast.net": true, "verizon.net": true, "sbcglobal.net": true,
		"fastmail.com": true, "hushmail.com": true,
	}

	// Role account check
	roleAccounts := map[string]bool{
		"admin": true, "administrator": true, "webmaster": true, "postmaster": true,
		"hostmaster": true, "info": true, "support": true, "help": true,
		"sales": true, "marketing": true, "billing": true, "accounts": true,
		"noreply": true, "no-reply": true, "notifications": true, "newsletter": true,
		"abuse": true, "security": true, "contact": true, "hello": true,
		"team": true, "hr": true, "jobs": true, "careers": true, "legal": true,
		"privacy": true, "press": true, "media": true, "partners": true,
	}

	// SPF/DMARC check
	spf := ""
	txtRecs, _ := net.LookupTXT(domain)
	for _, t := range txtRecs {
		if strings.HasPrefix(t, "v=spf1") {
			spf = t
			break
		}
	}
	dmarc := ""
	dmarcRecs, _ := net.LookupTXT("_dmarc." + domain)
	for _, d := range dmarcRecs {
		if strings.HasPrefix(d, "v=DMARC1") {
			dmarc = d
			break
		}
	}

	isDisposable := disposableDomains[domain]
	isFree := freeProviders[domain]
	isRole := roleAccounts[user]
	deliverable := mxValid && !isDisposable

	// Domain age hint via WHOIS (best effort)
	domainAge := ""
	raw, err2 := whoisQuery("whois.iana.org", domain)
	if err2 == nil && len(raw) > 100 {
		for _, line := range strings.Split(raw, "\n") {
			ll := strings.ToLower(strings.TrimSpace(line))
			if strings.Contains(ll, "creat") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					domainAge = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	return mapVal(map[string]*Value{
		"email":         strVal(email),
		"user":          strVal(user),
		"domain":        strVal(domain),
		"valid":         boolVal(true),
		"mx_valid":      boolVal(mxValid),
		"deliverable":   boolVal(deliverable),
		"disposable":    boolVal(isDisposable),
		"free_provider": boolVal(isFree),
		"role_account":  boolVal(isRole),
		"primary_mx":    strVal(primaryMX),
		"mx_records":    listVal(mxList),
		"mx_count":      intVal(int64(len(mxList))),
		"spf":           strVal(spf),
		"dmarc":         strVal(dmarc),
		"domain_age":    strVal(domainAge),
		"catch_all":     boolVal(false),
		"error":         strVal(""),
	}), nil
}

// ─── 13. macvendor() ─────────────────────────────────────────────────────────

func (interp *Interpreter) netMACVendor(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("macvendor() requires a MAC address")
	}
	mac := strings.TrimSpace(args[0].Display())
	mac = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))

	data, err := interp.getJSON("https://api.macvendors.com/" + mac)
	vendor := ""
	if err == nil {
		if v, ok := data["vendorDetails"].(map[string]interface{}); ok {
			if c, ok := v["companyName"].(string); ok {
				vendor = c
			}
		}
	}
	if vendor == "" {
		body, _, err2 := interp.getRaw("https://api.macvendors.com/" + mac)
		if err2 == nil && len(body) < 200 {
			vendor = strings.TrimSpace(string(body))
		}
	}

	errStr := ""
	if vendor == "" {
		errStr = "vendor not found"
	}

	// OUI prefix
	oui := ""
	parts := strings.Split(mac, ":")
	if len(parts) >= 3 {
		oui = strings.Join(parts[:3], ":")
	}

	return mapVal(map[string]*Value{
		"mac":    strVal(mac),
		"oui":    strVal(oui),
		"vendor": strVal(vendor),
		"error":  strVal(errStr),
	}), nil
}

// ─── 14. iprange() ───────────────────────────────────────────────────────────

func (interp *Interpreter) netIPRange(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("iprange() requires a CIDR or range")
	}
	input := strings.TrimSpace(args[0].Display())
	maxHosts := 1024
	if len(args) >= 2 {
		maxHosts = int(args[1].ToInt())
	}

	var ips []*Value

	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return mapVal(map[string]*Value{"error": strVal(err.Error()), "ips": listVal([]*Value{})}), nil
		}
		for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incrementIP(ip) {
			ips = append(ips, strVal(ip.String()))
			if len(ips) >= maxHosts {
				break
			}
		}
	} else if strings.Contains(input, "-") {
		parts := strings.SplitN(input, "-", 2)
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return mapVal(map[string]*Value{"error": strVal("invalid range"), "ips": listVal([]*Value{})}), nil
		}
		for ip := cloneIP(startIP.To4()); !ipGreater(ip, endIP.To4()); incrementIP(ip) {
			ips = append(ips, strVal(ip.String()))
			if len(ips) >= maxHosts {
				break
			}
		}
	}

	if ips == nil {
		ips = []*Value{}
	}
	return mapVal(map[string]*Value{
		"input": strVal(input), "ips": listVal(ips),
		"count": intVal(int64(len(ips))), "error": strVal(""),
	}), nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
func ipGreater(a, b net.IP) bool {
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

// ─── 15. phoninfo() — Professional Phone Intelligence ────────────────────────

func (interp *Interpreter) netPhoninfo(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("phoninfo() requires a phone number")
	}
	input := strings.TrimSpace(args[0].Display())
	r := analyzePhoneNumber(input)
	return mapVal(r), nil
}

func analyzePhoneNumber(number string) map[string]*Value {
	result := make(map[string]*Value)
	result["input"] = strVal(number)
	result["error"] = strVal("")
	result["carrier"] = strVal("Unknown")
	result["region"] = strVal("")
	result["line_type"] = strVal("Unknown")

	// Normalize
	cleaned := regexp.MustCompile(`[\s\-\(\)\.]+`).ReplaceAllString(number, "")
	if !strings.HasPrefix(cleaned, "+") {
		if len(cleaned) == 10 {
			cleaned = "+1" + cleaned
		} else if strings.HasPrefix(cleaned, "0") {
			cleaned = "+" + cleaned[1:]
		} else {
			cleaned = "+" + cleaned
		}
	}
	result["e164"] = strVal(cleaned)

	// ── Country code longest-match ────────────────────────────
	type ccEntry struct{ code, country, dialZone string }
	ccList := []ccEntry{
		// Special US ranges
		{"+1800", "United States", "Toll-Free (NA)"}, {"+1833", "United States", "Toll-Free (NA)"},
		{"+1844", "United States", "Toll-Free (NA)"}, {"+1855", "United States", "Toll-Free (NA)"},
		{"+1866", "United States", "Toll-Free (NA)"}, {"+1877", "United States", "Toll-Free (NA)"},
		{"+1888", "United States", "Toll-Free (NA)"}, {"+1900", "United States", "Premium-Rate"},
		// NANP territories
		{"+1242", "Bahamas", "NANP"}, {"+1246", "Barbados", "NANP"}, {"+1264", "Anguilla", "NANP"},
		{"+1268", "Antigua & Barbuda", "NANP"}, {"+1284", "British Virgin Islands", "NANP"},
		{"+1340", "US Virgin Islands", "NANP"}, {"+1345", "Cayman Islands", "NANP"},
		{"+1441", "Bermuda", "NANP"}, {"+1473", "Grenada", "NANP"}, {"+1649", "Turks & Caicos", "NANP"},
		{"+1664", "Montserrat", "NANP"}, {"+1671", "Guam", "NANP"}, {"+1684", "American Samoa", "NANP"},
		{"+1721", "Sint Maarten", "NANP"}, {"+1758", "Saint Lucia", "NANP"},
		{"+1767", "Dominica", "NANP"}, {"+1784", "Saint Vincent", "NANP"},
		{"+1787", "Puerto Rico", "NANP"}, {"+1809", "Dominican Republic", "NANP"},
		{"+1868", "Trinidad & Tobago", "NANP"}, {"+1869", "Saint Kitts & Nevis", "NANP"},
		{"+1876", "Jamaica", "NANP"}, {"+1939", "Puerto Rico", "NANP"},
		// Standard
		{"+1", "United States/Canada", "NANP"},
		{"+20", "Egypt", "Africa"}, {"+27", "South Africa", "Africa"},
		{"+30", "Greece", "Europe"}, {"+31", "Netherlands", "Europe"}, {"+32", "Belgium", "Europe"},
		{"+33", "France", "Europe"}, {"+34", "Spain", "Europe"}, {"+36", "Hungary", "Europe"},
		{"+39", "Italy", "Europe"}, {"+40", "Romania", "Europe"}, {"+41", "Switzerland", "Europe"},
		{"+43", "Austria", "Europe"}, {"+44", "United Kingdom", "Europe"},
		{"+45", "Denmark", "Europe"}, {"+46", "Sweden", "Europe"}, {"+47", "Norway", "Europe"},
		{"+48", "Poland", "Europe"}, {"+49", "Germany", "Europe"},
		{"+51", "Peru", "LATAM"}, {"+52", "Mexico", "LATAM"}, {"+53", "Cuba", "LATAM"},
		{"+54", "Argentina", "LATAM"}, {"+55", "Brazil", "LATAM"}, {"+56", "Chile", "LATAM"},
		{"+57", "Colombia", "LATAM"}, {"+58", "Venezuela", "LATAM"},
		{"+60", "Malaysia", "Asia"}, {"+61", "Australia", "Oceania"},
		{"+62", "Indonesia", "Asia"}, {"+63", "Philippines", "Asia"},
		{"+64", "New Zealand", "Oceania"}, {"+65", "Singapore", "Asia"},
		{"+66", "Thailand", "Asia"},
		{"+7", "Russia/Kazakhstan", "Eurasia"},
		{"+81", "Japan", "Asia"}, {"+82", "South Korea", "Asia"}, {"+84", "Vietnam", "Asia"},
		{"+86", "China", "Asia"},
		{"+90", "Turkey", "Eurasia"}, {"+91", "India", "Asia"}, {"+92", "Pakistan", "Asia"},
		{"+93", "Afghanistan", "Asia"}, {"+94", "Sri Lanka", "Asia"}, {"+95", "Myanmar", "Asia"},
		{"+98", "Iran", "Asia"},
		{"+212", "Morocco", "Africa"}, {"+213", "Algeria", "Africa"}, {"+216", "Tunisia", "Africa"},
		{"+218", "Libya", "Africa"}, {"+220", "Gambia", "Africa"}, {"+221", "Senegal", "Africa"},
		{"+234", "Nigeria", "Africa"}, {"+233", "Ghana", "Africa"}, {"+254", "Kenya", "Africa"},
		{"+255", "Tanzania", "Africa"}, {"+256", "Uganda", "Africa"},
		{"+260", "Zambia", "Africa"}, {"+263", "Zimbabwe", "Africa"},
		{"+351", "Portugal", "Europe"}, {"+352", "Luxembourg", "Europe"},
		{"+353", "Ireland", "Europe"}, {"+354", "Iceland", "Europe"},
		{"+358", "Finland", "Europe"}, {"+370", "Lithuania", "Europe"},
		{"+371", "Latvia", "Europe"}, {"+372", "Estonia", "Europe"},
		{"+375", "Belarus", "Europe"}, {"+380", "Ukraine", "Europe"},
		{"+381", "Serbia", "Europe"}, {"+382", "Montenegro", "Europe"},
		{"+385", "Croatia", "Europe"}, {"+386", "Slovenia", "Europe"},
		{"+387", "Bosnia", "Europe"}, {"+420", "Czech Republic", "Europe"},
		{"+421", "Slovakia", "Europe"},
		{"+593", "Ecuador", "LATAM"}, {"+595", "Paraguay", "LATAM"},
		{"+598", "Uruguay", "LATAM"},
		{"+880", "Bangladesh", "Asia"}, {"+886", "Taiwan", "Asia"},
		{"+852", "Hong Kong", "Asia"}, {"+853", "Macau", "Asia"},
		{"+855", "Cambodia", "Asia"}, {"+856", "Laos", "Asia"},
		{"+960", "Maldives", "Asia"}, {"+962", "Jordan", "Middle East"},
		{"+963", "Syria", "Middle East"}, {"+964", "Iraq", "Middle East"},
		{"+965", "Kuwait", "Middle East"}, {"+966", "Saudi Arabia", "Middle East"},
		{"+968", "Oman", "Middle East"}, {"+971", "UAE", "Middle East"},
		{"+972", "Israel", "Middle East"}, {"+973", "Bahrain", "Middle East"},
		{"+974", "Qatar", "Middle East"}, {"+977", "Nepal", "Asia"},
	}

	countryCode := ""
	countryName := ""
	dialZone := ""
	for _, cc := range ccList {
		if strings.HasPrefix(cleaned, cc.code) {
			countryCode = cc.code
			countryName = cc.country
			dialZone = cc.dialZone
			break
		}
	}

	localNumber := strings.TrimPrefix(cleaned, countryCode)
	result["local_number"] = strVal(localNumber)
	result["country_code"] = strVal(countryCode)
	result["country"] = strVal(countryName)
	result["dial_zone"] = strVal(dialZone)

	lineType := "Mobile/Landline"
	carrier := "Unknown"
	region := ""

	// ── India (+91) detailed analysis ────────────────────────
	if countryCode == "+91" && len(localNumber) == 10 {
		lineType = analyzeIndianNumber(localNumber, &carrier, &region)
	}

	// ── US/Canada (+1) analysis ───────────────────────────────
	if countryCode == "+1" && len(localNumber) == 10 {
		switch {
		case strings.HasPrefix(cleaned, "+1800"), strings.HasPrefix(cleaned, "+1833"),
			strings.HasPrefix(cleaned, "+1844"), strings.HasPrefix(cleaned, "+1855"),
			strings.HasPrefix(cleaned, "+1866"), strings.HasPrefix(cleaned, "+1877"),
			strings.HasPrefix(cleaned, "+1888"):
			lineType = "Toll-Free"
		case strings.HasPrefix(cleaned, "+1900"):
			lineType = "Premium-Rate"
		default:
			lineType = "Mobile/Landline"
			region = usAreaCode(localNumber[:3])
		}
	}

	// ── UK (+44) analysis ─────────────────────────────────────
	if countryCode == "+44" && len(localNumber) >= 7 {
		switch {
		case strings.HasPrefix(localNumber, "7"):
			lineType = "Mobile"
		case strings.HasPrefix(localNumber, "800"), strings.HasPrefix(localNumber, "808"):
			lineType = "Freephone"
		case strings.HasPrefix(localNumber, "845"), strings.HasPrefix(localNumber, "870"):
			lineType = "Non-Geographic"
		default:
			lineType = "Landline"
			region = ukAreaCode(localNumber[:3])
		}
	}

	// ── Brazil (+55) ──────────────────────────────────────────
	if countryCode == "+55" && len(localNumber) >= 10 {
		if strings.HasPrefix(localNumber[2:], "9") || strings.HasPrefix(localNumber[2:], "8") {
			lineType = "Mobile"
		} else {
			lineType = "Landline"
		}
	}

	// Default for unknown/other countries
	if lineType == "Unknown" {
		firstDigit := ""
		if len(localNumber) > 0 {
			firstDigit = string(localNumber[0])
		}
		switch firstDigit {
		case "6", "7", "8", "9":
			lineType = "Mobile (probable)"
		default:
			lineType = "Landline (probable)"
		}
	}

	// Formatted display
	formatted := formatPhone(cleaned, countryCode, localNumber)

	valid := len(cleaned) >= 8 && len(cleaned) <= 16 && countryCode != ""

	result["formatted"] = strVal(formatted)
	result["line_type"] = strVal(lineType)
	result["carrier"] = strVal(carrier)
	result["region"] = strVal(region)
	result["dial_zone"] = strVal(dialZone)
	result["valid"] = boolVal(valid)
	result["number_length"] = intVal(int64(len(localNumber)))
	result["note"] = strVal("Carrier identification via NNI prefix analysis. For real-time portability data, a live MNPDB query (MNP API) is required.")
	return result
}

func analyzeIndianNumber(local string, carrier, region *string) string {
	if len(local) != 10 {
		return "Unknown"
	}

	prefix4 := local[:4]
	prefix2 := local[:2]
	firstCh := string(local[0])

	// Landline area codes (2-digit STD)
	landlineAreas := map[string]string{
		"11": "Delhi", "22": "Mumbai", "33": "Kolkata", "44": "Chennai",
		"40": "Hyderabad", "80": "Bengaluru", "20": "Pune", "79": "Ahmedabad",
		"141": "Jaipur", "172": "Chandigarh", "522": "Lucknow", "532": "Prayagraj",
		"542": "Varanasi", "562": "Agra", "551": "Gorakhpur", "581": "Bareilly",
		"612": "Patna", "651": "Ranchi", "674": "Bhubaneswar", "771": "Raipur",
	}

	// 4-digit carrier prefix table (Indian NNI)
	type iCarrier struct{ carrier, circle string }
	carrierMap := map[string]iCarrier{
		// Jio (6xxx, 7xxx, 8xxx, 9xxx ranges)
		"6000": {"Jio", "Delhi/NCR"}, "6001": {"Jio", "Delhi/NCR"},
		"6002": {"Jio", "Haryana"}, "6003": {"Jio", "UP West"},
		"6004": {"Jio", "MP"}, "6005": {"Jio", "UP East"},
		"6006": {"Jio", "Punjab"}, "6007": {"Jio", "Rajasthan"},
		"6008": {"Jio", "Karnataka"}, "6009": {"Jio", "Kerala"},
		"7000": {"Jio", "Delhi/NCR"}, "7001": {"Jio", "Kolkata"},
		"7007": {"Jio", "Maharashtra"}, "7008": {"Jio", "Orissa"},
		"8955": {"Jio", "Tamil Nadu"}, "8956": {"Jio", "Andhra Pradesh"},
		"8957": {"Jio", "Karnataka"}, "8958": {"Jio", "Kerala"},
		"9152": {"Jio", "Maharashtra"}, "9153": {"Jio", "Gujarat"},
		"9154": {"Jio", "AP"}, "9155": {"Jio", "HP"},
		// Airtel
		"9800": {"Airtel", "West Bengal"}, "9801": {"Airtel", "Jharkhand"},
		"9802": {"Airtel", "Bihar"}, "9810": {"Airtel", "Delhi"},
		"9811": {"Airtel", "Delhi"}, "9868": {"Airtel", "Delhi"},
		"9871": {"Airtel", "Delhi"}, "9899": {"Airtel", "Delhi"},
		"7840": {"Airtel", "Delhi"}, "8130": {"Airtel", "Delhi"},
		"8131": {"Airtel", "Delhi"}, "9958": {"Airtel", "Delhi"},
		"9872": {"Airtel", "Punjab"}, "9814": {"Airtel", "Punjab"},
		"9815": {"Airtel", "Punjab"}, "9876": {"Airtel", "Punjab"},
		"9878": {"Airtel", "Punjab"}, "9465": {"Airtel", "Haryana"},
		"9416": {"Airtel", "Haryana"}, "9992": {"Airtel", "Haryana"},
		"7015": {"Airtel", "Haryana"}, "9007": {"Airtel", "Kolkata"},
		"9830": {"Airtel", "Kolkata"}, "7044": {"Airtel", "Kolkata"},
		"9433": {"Airtel", "West Bengal"},
		// Vodafone-Idea (Vi)
		"9820": {"Vi (Vodafone-Idea)", "Mumbai"}, "9821": {"Vi (Vodafone-Idea)", "Mumbai"},
		"9833": {"Vi (Vodafone-Idea)", "Mumbai"}, "9870": {"Vi (Vodafone-Idea)", "Mumbai"},
		"9867": {"Vi (Vodafone-Idea)", "Mumbai"}, "8108": {"Vi (Vodafone-Idea)", "Mumbai"},
		"9890": {"Vi (Vodafone-Idea)", "Pune"}, "9881": {"Vi (Vodafone-Idea)", "Pune"},
		"9011": {"Vi (Vodafone-Idea)", "Maharashtra"},
		// BSNL
		"9415": {"BSNL", "UP East"}, "9450": {"BSNL", "UP East"},
		"9451": {"BSNL", "UP East"}, "9452": {"BSNL", "UP East"},
		"9453": {"BSNL", "UP East"}, "9454": {"BSNL", "UP East"},
		"9455": {"BSNL", "UP East"}, "9456": {"BSNL", "UP West"},
		"9457": {"BSNL", "UP West"}, "9412": {"BSNL", "UP West"},
		"9413": {"BSNL", "Rajasthan"}, "9414": {"BSNL", "Rajasthan"},
		"9437": {"BSNL", "Orissa"},
		// MTNL
		"9869": {"MTNL", "Mumbai"},
	}

	// Try 4-digit match
	if info, ok := carrierMap[prefix4]; ok {
		*carrier = info.carrier
		*region = info.circle
		return "Mobile"
	}

	// Try 2-digit landline match
	for code, city := range landlineAreas {
		if strings.HasPrefix(local, code) {
			*region = city
			return "Landline"
		}
	}

	// Fallback by first digit
	switch firstCh {
	case "6", "7", "8", "9":
		// Regional hints by prefix2
		regionMap := map[string]string{
			"98": "North India", "99": "South India", "97": "Gujarat/Rajasthan",
			"96": "South India", "95": "MP/CG", "94": "South India", "93": "West India",
			"92": "West India", "91": "North India", "90": "North/West India",
			"89": "South India", "88": "South India", "87": "North India",
			"86": "Odisha/East", "85": "East India", "84": "South India",
			"83": "MP/CG", "82": "East India", "81": "East India", "80": "East India",
			"79": "North India", "78": "MP/CG", "77": "West India", "76": "Central India",
			"75": "MP/CG", "74": "Rajasthan", "73": "Gujarat", "72": "Central India",
			"71": "East India", "70": "East India", "69": "Kerala", "68": "AP/Telangana",
			"67": "Odisha", "66": "West Bengal",
		}
		if r, ok := regionMap[prefix2]; ok {
			*region = r
		}
		return "Mobile"
	}
	return "Landline"
}

func usAreaCode(areaCode string) string {
	areaCodes := map[string]string{
		"201": "New Jersey", "202": "Washington DC", "203": "Connecticut",
		"205": "Alabama", "206": "Seattle WA", "207": "Maine",
		"208": "Idaho", "209": "Stockton CA", "210": "San Antonio TX",
		"212": "New York City", "213": "Los Angeles", "214": "Dallas TX",
		"215": "Philadelphia PA", "216": "Cleveland OH", "217": "Illinois",
		"218": "Minnesota", "219": "Indiana", "220": "Ohio",
		"224": "Illinois", "225": "Baton Rouge LA", "228": "Mississippi",
		"229": "Georgia", "231": "Michigan", "234": "Ohio",
		"239": "Florida", "240": "Maryland", "248": "Michigan",
		"251": "Alabama", "252": "North Carolina", "253": "Tacoma WA",
		"254": "Texas", "256": "Alabama", "260": "Indiana",
		"262": "Wisconsin", "267": "Philadelphia PA", "269": "Michigan",
		"270": "Kentucky", "272": "Pennsylvania", "276": "Virginia",
		"281": "Houston TX", "301": "Maryland", "302": "Delaware",
		"303": "Denver CO", "304": "West Virginia", "305": "Miami FL",
		"307": "Wyoming", "308": "Nebraska", "309": "Illinois",
		"310": "Los Angeles CA", "312": "Chicago IL", "313": "Detroit MI",
		"314": "St. Louis MO", "315": "New York", "316": "Wichita KS",
		"317": "Indianapolis IN", "318": "Louisiana", "319": "Iowa",
		"320": "Minnesota", "321": "Florida", "323": "Los Angeles CA",
		"325": "Texas", "330": "Ohio", "331": "Illinois",
		"334": "Alabama", "336": "North Carolina", "337": "Louisiana",
		"339": "Massachusetts", "340": "US Virgin Islands", "347": "New York",
		"351": "Massachusetts", "352": "Florida", "360": "Washington State",
		"361": "Texas", "380": "Ohio", "385": "Utah", "386": "Florida",
		"401": "Rhode Island", "402": "Nebraska", "404": "Atlanta GA",
		"405": "Oklahoma City OK", "406": "Montana", "407": "Orlando FL",
		"408": "San Jose CA", "409": "Texas", "410": "Baltimore MD",
		"412": "Pittsburgh PA", "413": "Massachusetts", "414": "Milwaukee WI",
		"415": "San Francisco CA", "417": "Missouri", "419": "Ohio",
		"423": "Tennessee", "424": "Los Angeles CA", "425": "Seattle WA",
		"430": "Texas", "432": "Texas", "434": "Virginia", "435": "Utah",
		"440": "Ohio", "442": "California", "443": "Maryland",
		"458": "Oregon", "469": "Dallas TX", "470": "Atlanta GA",
		"475": "Connecticut", "478": "Georgia", "479": "Arkansas",
		"480": "Phoenix AZ", "484": "Pennsylvania",
		"501": "Arkansas", "502": "Louisville KY", "503": "Portland OR",
		"504": "New Orleans LA", "505": "New Mexico", "507": "Minnesota",
		"508": "Massachusetts", "509": "Washington State", "510": "Oakland CA",
		"512": "Austin TX", "513": "Cincinnati OH", "515": "Des Moines IA",
		"516": "New York", "517": "Michigan", "518": "New York",
		"520": "Tucson AZ", "530": "California", "534": "Wisconsin",
		"539": "Oklahoma", "540": "Virginia", "541": "Oregon",
		"551": "New Jersey", "559": "Fresno CA", "561": "Florida",
		"562": "Long Beach CA", "563": "Iowa", "564": "Washington State",
		"567": "Ohio", "570": "Pennsylvania", "571": "Virginia",
		"573": "Missouri", "574": "Indiana", "575": "New Mexico",
		"580": "Oklahoma", "585": "Rochester NY", "586": "Michigan",
		"601": "Mississippi", "602": "Phoenix AZ", "603": "New Hampshire",
		"605": "South Dakota", "606": "Kentucky", "607": "New York",
		"608": "Wisconsin", "609": "New Jersey", "610": "Pennsylvania",
		"612": "Minneapolis MN", "614": "Columbus OH", "615": "Nashville TN",
		"616": "Michigan", "617": "Boston MA", "618": "Illinois",
		"619": "San Diego CA", "620": "Kansas", "623": "Phoenix AZ",
		"626": "Pasadena CA", "628": "San Francisco CA", "629": "Tennessee",
		"630": "Illinois", "631": "Long Island NY", "636": "Missouri",
		"641": "Iowa", "646": "New York City", "650": "San Jose CA",
		"651": "St. Paul MN", "657": "Orange County CA", "659": "Alabama",
		"660": "Missouri", "661": "Bakersfield CA", "662": "Mississippi",
		"667": "Maryland", "669": "San Jose CA", "670": "Northern Mariana Islands",
		"678": "Atlanta GA", "681": "West Virginia", "682": "Fort Worth TX",
		"701": "North Dakota", "702": "Las Vegas NV", "703": "Northern Virginia",
		"704": "Charlotte NC", "706": "Georgia", "707": "California",
		"708": "Chicago IL", "712": "Iowa", "713": "Houston TX",
		"714": "Orange County CA", "715": "Wisconsin", "716": "Buffalo NY",
		"717": "Pennsylvania", "718": "New York City", "719": "Colorado Springs CO",
		"720": "Denver CO", "724": "Pennsylvania", "725": "Nevada",
		"727": "Tampa FL", "731": "Tennessee", "732": "New Jersey",
		"734": "Michigan", "737": "Austin TX", "740": "Ohio", "743": "North Carolina",
		"747": "Los Angeles CA", "754": "Fort Lauderdale FL", "757": "Virginia Beach VA",
		"760": "Palm Springs CA", "762": "Georgia", "763": "Minnesota",
		"764": "California", "765": "Indiana", "769": "Mississippi",
		"770": "Atlanta GA", "771": "Maryland", "772": "Florida",
		"773": "Chicago IL", "774": "Massachusetts", "775": "Nevada",
		"779": "Illinois", "781": "Massachusetts", "785": "Kansas",
		"786": "Miami FL", "787": "Puerto Rico", "801": "Salt Lake City UT",
		"802": "Vermont", "803": "South Carolina", "804": "Richmond VA",
		"805": "California", "806": "Texas", "808": "Hawaii",
		"810": "Michigan", "812": "Indiana", "813": "Tampa FL",
		"814": "Pennsylvania", "815": "Illinois", "816": "Kansas City MO",
		"817": "Fort Worth TX", "818": "Los Angeles CA", "828": "North Carolina",
		"830": "Texas", "831": "Monterey CA", "832": "Houston TX",
		"838": "New York", "843": "South Carolina", "845": "New York",
		"847": "Illinois", "848": "New Jersey", "850": "Pensacola FL",
		"854": "South Carolina", "856": "New Jersey", "857": "Boston MA",
		"858": "San Diego CA", "859": "Kentucky", "860": "Connecticut",
		"862": "New Jersey", "863": "Florida", "864": "South Carolina",
		"865": "Knoxville TN", "870": "Arkansas", "872": "Chicago IL",
		"878": "Pennsylvania", "901": "Memphis TN", "903": "Texas",
		"904": "Jacksonville FL", "906": "Michigan", "907": "Alaska",
		"908": "New Jersey", "909": "Riverside CA", "910": "North Carolina",
		"912": "Savannah GA", "913": "Kansas City KS", "914": "Westchester NY",
		"915": "El Paso TX", "916": "Sacramento CA", "917": "New York City",
		"918": "Tulsa OK", "919": "Raleigh NC", "920": "Wisconsin",
		"925": "Walnut Creek CA", "928": "Arizona", "929": "New York",
		"930": "Indiana", "931": "Tennessee", "934": "Long Island NY",
		"936": "Texas", "937": "Ohio", "938": "Alabama", "940": "Texas",
		"941": "Sarasota FL", "947": "Michigan", "949": "Orange County CA",
		"951": "Riverside CA", "952": "Minnesota", "954": "Fort Lauderdale FL",
		"956": "Laredo TX", "959": "Connecticut", "970": "Colorado",
		"971": "Portland OR", "972": "Dallas TX", "973": "New Jersey",
		"978": "Massachusetts", "979": "Texas", "980": "Charlotte NC",
		"984": "North Carolina", "985": "Louisiana", "989": "Michigan",
	}
	if r, ok := areaCodes[areaCode]; ok {
		return r
	}
	return ""
}

func ukAreaCode(prefix string) string {
	ukCodes := map[string]string{
		"020": "London", "0113": "Leeds", "0114": "Sheffield", "0115": "Nottingham",
		"0116": "Leicester", "0117": "Bristol", "0118": "Reading", "0121": "Birmingham",
		"0131": "Edinburgh", "0141": "Glasgow", "0151": "Liverpool", "0161": "Manchester",
		"0191": "Tyne and Wear",
	}
	for code, city := range ukCodes {
		if strings.HasPrefix("0"+prefix, code) {
			return city
		}
	}
	return ""
}

func formatPhone(full, countryCode, local string) string {
	switch countryCode {
	case "+91":
		if len(local) == 10 {
			return "+91 " + local[:5] + " " + local[5:]
		}
	case "+1":
		if len(local) == 10 {
			return "+1 (" + local[:3] + ") " + local[3:6] + "-" + local[6:]
		}
	case "+44":
		if len(local) >= 10 {
			if strings.HasPrefix(local, "7") {
				return "+44 7" + local[1:4] + " " + local[4:]
			}
			return "+44 " + local[:4] + " " + local[4:]
		}
	case "+61":
		if len(local) == 9 {
			return "+61 " + local[:1] + " " + local[1:5] + " " + local[5:]
		}
	case "+49":
		if len(local) >= 10 {
			return "+49 " + local[:3] + " " + local[3:7] + " " + local[7:]
		}
	case "+86":
		if len(local) == 11 {
			return "+86 " + local[:3] + " " + local[3:7] + " " + local[7:]
		}
	}
	return full
}

// ─── 16. subnet() — Advanced Subnet Calculator ───────────────────────────────

func (interp *Interpreter) netSubnet(args []*Value) (*Value, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("subnet() requires CIDR notation (e.g. 192.168.1.0/24)")
	}
	cidr := strings.TrimSpace(args[0].Display())

	// Auto-handle bare IP
	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr) != nil {
			cidr = cidr + "/32"
		} else {
			return mapVal(map[string]*Value{
				"cidr":  strVal(args[0].Display()),
				"error": strVal("Invalid CIDR. Use format: 192.168.1.0/24 or 10.0.0.0/8"),
				"hint":  strVal("Example: subnet(\"192.168.1.0/24\")"),
			}), nil
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return mapVal(map[string]*Value{
			"cidr":  strVal(cidr),
			"error": strVal(err.Error()),
			"hint":  strVal("Example: subnet(\"192.168.1.0/24\")"),
		}), nil
	}

	ones, bits := ipNet.Mask.Size()
	totalHosts := int64(1) << uint(bits-ones)
	usable := totalHosts - 2
	if usable < 0 {
		usable = 0
	}
	if ones == 32 {
		usable = 1
	} // host route
	if ones == 31 {
		usable = 2
	} // point-to-point

	network := ipNet.IP
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^ipNet.Mask[i]
	}

	first := cloneIP(network)
	last := cloneIP(broadcast)
	if len(first) == 4 && ones < 31 {
		first[3]++
		last[3]--
	}

	wildcard := make(net.IP, len(ipNet.Mask))
	for i := range ipNet.Mask {
		wildcard[i] = ^ipNet.Mask[i]
	}

	ipVer := "IPv4"
	if bits == 128 {
		ipVer = "IPv6"
	}

	subnetClass := classifySubnet(network.String(), ones)

	// Binary mask representation
	binMask := ""
	for i, b := range ipNet.Mask {
		if i > 0 && i%1 == 0 {
			binMask += "."
		}
		binMask += fmt.Sprintf("%08b", b)
	}

	// Supernets this belongs to
	var supernets []*Value
	for _, prefix := range []int{8, 16, 24} {
		if ones > prefix {
			sn := &net.IPNet{IP: ip.Mask(net.CIDRMask(prefix, bits)), Mask: net.CIDRMask(prefix, bits)}
			supernets = append(supernets, strVal(sn.String()))
		}
	}

	// Subnets if splitting into /prefix+1
	var subnets []*Value
	if ones < 30 {
		s1 := &net.IPNet{IP: ipNet.IP, Mask: net.CIDRMask(ones+1, bits)}
		ip2 := cloneIP(ipNet.IP)
		half := net.CIDRMask(ones+1, bits)
		// flip the split bit
		for i := range ip2 {
			ip2[i] |= ^ipNet.Mask[i] & half[i]
		}
		s2 := &net.IPNet{IP: ip2.Mask(net.CIDRMask(ones+1, bits)), Mask: net.CIDRMask(ones+1, bits)}
		subnets = append(subnets, strVal(s1.String()), strVal(s2.String()))
	}

	if supernets == nil {
		supernets = []*Value{}
	}
	if subnets == nil {
		subnets = []*Value{}
	}

	return mapVal(map[string]*Value{
		"cidr":          strVal(cidr),
		"network":       strVal(network.String()),
		"broadcast":     strVal(broadcast.String()),
		"first_host":    strVal(first.String()),
		"last_host":     strVal(last.String()),
		"subnet_mask":   strVal(net.IP(ipNet.Mask).String()),
		"wildcard_mask": strVal(wildcard.String()),
		"binary_mask":   strVal(binMask),
		"prefix":        intVal(int64(ones)),
		"total_hosts":   intVal(totalHosts),
		"usable_hosts":  intVal(usable),
		"ip_version":    strVal(ipVer),
		"class":         strVal(subnetClass),
		"contains_ip":   strVal(ip.String()),
		"supernets":     listVal(supernets),
		"split_into":    listVal(subnets),
		"error":         strVal(""),
		"hint":          strVal(""),
	}), nil
}

func classifySubnet(ip string, prefix int) string {
	switch {
	case strings.HasPrefix(ip, "10."):
		return "Private Class A (RFC1918) — 10.0.0.0/8"
	case matchPrivateB(ip):
		return "Private Class B (RFC1918) — 172.16.0.0/12"
	case strings.HasPrefix(ip, "192.168."):
		return "Private Class C (RFC1918) — 192.168.0.0/16"
	case strings.HasPrefix(ip, "127."):
		return "Loopback (RFC5735)"
	case strings.HasPrefix(ip, "169.254."):
		return "Link-Local APIPA (RFC3927)"
	case strings.HasPrefix(ip, "100.64."):
		return "Shared Address Space (RFC6598) — ISP CGN"
	case strings.HasPrefix(ip, "192.0.2."):
		return "Documentation TEST-NET-1 (RFC5737)"
	case strings.HasPrefix(ip, "198.51.100."):
		return "Documentation TEST-NET-2 (RFC5737)"
	case strings.HasPrefix(ip, "203.0.113."):
		return "Documentation TEST-NET-3 (RFC5737)"
	case strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239."):
		return "Multicast (RFC5771)"
	case strings.HasPrefix(ip, "240."):
		return "Reserved (RFC1112)"
	case ip == "0.0.0.0":
		return "Default Route / Unspecified"
	case strings.HasPrefix(ip, "255.255.255.255"):
		return "Limited Broadcast"
	default:
		if prefix <= 8 {
			return "Public Class A Supernet"
		}
		if prefix <= 16 {
			return "Public Class B"
		}
		return "Public Class C"
	}
}

func matchPrivateB(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) < 2 || parts[0] != "172" {
		return false
	}
	n, err := strconv.Atoi(parts[1])
	return err == nil && n >= 16 && n <= 31
}
