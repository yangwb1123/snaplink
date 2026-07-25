package device

import "testing"

func TestParseUserAgent_iPhoneSafari(t *testing.T) {
	ua := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeMobile {
		t.Errorf("Type = %v, want mobile", d.Type)
	}
	if d.Platform != "iOS" {
		t.Errorf("Platform = %q, want iOS", d.Platform)
	}
	if d.OSVersion != "17.4" {
		t.Errorf("OSVersion = %q, want 17.4", d.OSVersion)
	}
	if d.BrowserName != "Safari" {
		t.Errorf("BrowserName = %q, want Safari", d.BrowserName)
	}
	if d.DeviceName != "iPhone" {
		t.Errorf("DeviceName = %q, want iPhone", d.DeviceName)
	}
	if !d.IsMobile {
		t.Error("IsMobile should be true")
	}
}

func TestParseUserAgent_AndroidChrome(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro Build/UPS1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeMobile {
		t.Errorf("Type = %v, want mobile", d.Type)
	}
	if d.Platform != "Android" {
		t.Errorf("Platform = %q, want Android", d.Platform)
	}
	if d.OSVersion != "14" {
		t.Errorf("OSVersion = %q, want 14", d.OSVersion)
	}
	if d.BrowserName != "Chrome" {
		t.Errorf("BrowserName = %q, want Chrome", d.BrowserName)
	}
	if d.BrowserVersion != "125.0.6422.165" {
		t.Errorf("BrowserVersion = %q", d.BrowserVersion)
	}
}

func TestParseUserAgent_WindowsEdge(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.79"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeBrowser {
		t.Errorf("Type = %v, want browser", d.Type)
	}
	if d.Platform != "Windows" {
		t.Errorf("Platform = %q, want Windows", d.Platform)
	}
	if d.OSVersion != "10" {
		t.Errorf("OSVersion = %q, want 10", d.OSVersion)
	}
	if d.BrowserName != "Edge" {
		t.Errorf("BrowserName = %q, want Edge", d.BrowserName)
	}
}

func TestParseUserAgent_macOSFirefox(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeBrowser {
		t.Errorf("Type = %v, want browser", d.Type)
	}
	if d.Platform != "macOS" {
		t.Errorf("Platform = %q, want macOS", d.Platform)
	}
	if d.BrowserName != "Firefox" {
		t.Errorf("BrowserName = %q, want Firefox", d.BrowserName)
	}
}

func TestParseUserAgent_Empty(t *testing.T) {
	d := ParseUserAgent("")
	if d.Type != DeviceTypeUnknown {
		t.Errorf("Type = %v, want unknown", d.Type)
	}
}

func TestParseUserAgent_Bot(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeBot {
		t.Errorf("Type = %v, want bot", d.Type)
	}
}

func TestParseUserAgent_iPad(t *testing.T) {
	ua := "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeTablet {
		t.Errorf("Type = %v, want tablet", d.Type)
	}
	if d.Platform != "iOS" {
		t.Errorf("Platform = %q, want iOS", d.Platform)
	}
}

func TestParseUserAgent_LinuxDesktop(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeBrowser {
		t.Errorf("Type = %v, want browser", d.Type)
	}
	if d.Platform != "Linux" {
		t.Errorf("Platform = %q, want Linux", d.Platform)
	}
}

func TestParseUserAgent_Opera(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0"
	d := ParseUserAgent(ua)
	if d.BrowserName != "Opera" {
		t.Errorf("BrowserName = %q, want Opera", d.BrowserName)
	}
}

func TestParseUserAgent_InternetExplorer(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
	d := ParseUserAgent(ua)
	if d.Platform != "Windows" {
		t.Errorf("Platform = %q, want Windows", d.Platform)
	}
	if d.BrowserName != "Internet Explorer" {
		t.Errorf("BrowserName = %q, want IE", d.BrowserName)
	}
}

func TestParseUserAgent_Curl(t *testing.T) {
	ua := "curl/8.4.0"
	d := ParseUserAgent(ua)
	if d.Type != DeviceTypeBot {
		t.Errorf("Type = %v, want bot", d.Type)
	}
}
