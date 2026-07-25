package device

import "strings"

// ParsedDevice holds the extracted fields from a User-Agent string.
type ParsedDevice struct {
	Type           DeviceType
	Platform       string
	OSVersion      string
	BrowserName    string
	BrowserVersion string
	DeviceName     string
	IsMobile       bool
}

// ParseUserAgent extracts device info from a User-Agent header.
func ParseUserAgent(ua string) ParsedDevice {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ParsedDevice{Type: DeviceTypeUnknown}
	}
	if isBot(ua) {
		return ParsedDevice{Type: DeviceTypeBot}
	}
	p := parsePlatform(ua)
	p.BrowserName, p.BrowserVersion = detectBrowser(ua)
	if p.Type == DeviceTypeDesktop && p.BrowserName != "" {
		p.Type = DeviceTypeBrowser
	}
	return p
}

// parsePlatform extracts OS/platform info from User-Agent.
func parsePlatform(ua string) ParsedDevice {
	// Order matters: check iOS before macOS (iPhone includes "Mac OS X").
	if strings.Contains(ua, "iPhone") {
		return parseIOS(ua, "iPhone", DeviceTypeMobile)
	}
	if strings.Contains(ua, "iPad") {
		return parseIOS(ua, "iPad", DeviceTypeTablet)
	}
	if strings.Contains(ua, "Android") {
		return parseAndroid(ua)
	}
	if strings.Contains(ua, "Windows") {
		return parseWindows(ua)
	}
	if strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X") {
		return parseMacOS(ua)
	}
	if strings.Contains(ua, "Linux") {
		return ParsedDevice{Type: DeviceTypeDesktop, Platform: "Linux", DeviceName: "Linux PC"}
	}
	return ParsedDevice{Type: DeviceTypeDesktop, Platform: "Unknown"}
}

func parseIOS(ua, model string, dtype DeviceType) ParsedDevice {
	ver := extractUntil(extractAfter(ua, "iPhone OS "), " ")
	ver = strings.ReplaceAll(ver, "_", ".")
	return ParsedDevice{
		Type: dtype, Platform: "iOS", OSVersion: ver,
		DeviceName: model, IsMobile: true,
	}
}

func parseAndroid(ua string) ParsedDevice {
	mobile := !strings.Contains(ua, "Tablet")
	dtype := DeviceTypeMobile
	if !mobile {
		dtype = DeviceTypeTablet
	}
	ver := extractAfter(ua, "Android ")
	ver = extractUntil(ver, " ;)")
	model := ""
	if idx := strings.Index(ua, "Build/"); idx > 0 {
		before := ua[:idx]
		if ls := strings.LastIndex(before, "; "); ls > 0 {
			model = strings.TrimSpace(before[ls+2:])
		}
	}
	return ParsedDevice{
		Type: dtype, Platform: "Android", OSVersion: ver,
		DeviceName: model, IsMobile: mobile,
	}
}

func parseWindows(ua string) ParsedDevice {
	ver := ""
	switch {
	case strings.Contains(ua, "Windows NT 10"):
		ver = "10"
	case strings.Contains(ua, "Windows NT 6.3"):
		ver = "8.1"
	case strings.Contains(ua, "Windows NT 6.1"):
		ver = "7"
	}
	return ParsedDevice{Type: DeviceTypeDesktop, Platform: "Windows", OSVersion: ver, DeviceName: "Windows PC"}
}

func parseMacOS(ua string) ParsedDevice {
	ver := extractAfter(ua, "Mac OS X ")
	ver = extractUntil(ver, " ;)")
	ver = strings.ReplaceAll(ver, "_", ".")
	name := "Mac"
	if strings.Contains(ua, "Intel") {
		name = "Mac (Intel)"
	}
	return ParsedDevice{Type: DeviceTypeDesktop, Platform: "macOS", OSVersion: ver, DeviceName: name}
}

func detectBrowser(ua string) (name, version string) {
	browsers := []struct {
		marker string
		name   string
	}{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Chrome/", "Chrome"},
		{"Firefox/", "Firefox"}, {"Safari/", "Safari"},
		{"MSIE ", "Internet Explorer"}, {"Trident/", "Internet Explorer"},
	}
	for _, b := range browsers {
		if idx := strings.Index(ua, b.marker); idx >= 0 {
			ver := ua[idx+len(b.marker):]
			ver = extractUntil(ver, " ;)")
			return b.name, ver
		}
	}
	return "", ""
}

func extractAfter(s, marker string) string {
	idx := strings.Index(s, marker)
	if idx < 0 {
		return ""
	}
	return s[idx+len(marker):]
}

func extractUntil(s, seps string) string {
	idx := strings.IndexAny(s, seps)
	if idx < 0 {
		return s
	}
	return s[:idx]
}

func isBot(ua string) bool {
	lua := strings.ToLower(ua)
	bots := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget",
		"headless", "googlebot", "bingbot", "slurp", "duckduckbot",
		"baiduspider", "yandexbot", "facebookexternalhit",
		"whatsapp", "telegrambot", "slack",
	}
	for _, b := range bots {
		if strings.Contains(lua, b) {
			return true
		}
	}
	return false
}
