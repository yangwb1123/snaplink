package defaultimpl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// reasonWeakDictionary is the operator-facing Reason stamped on a
// dictionary hit. It lands in audit metadata only — never on the wire.
const reasonWeakDictionary = "matched weak-password dictionary"

// DictionaryPasswordHealthChecker is the reference [spi.PasswordHealthChecker]:
// an offline exact-match lookup against a set of well-known weak passwords.
// No external dependency, no network call, no per-request allocation beyond
// the map probe.
//
// The lookup is a plain map membership test. There is no credential-oracle
// concern here even though it short-circuits on a match: the password has
// already been verified by the authenticator before this runs, so an
// attacker who reaches Check already holds the valid credential.
//
// Operators who want online breach detection (HIBP k-anonymity range
// queries, an internal compromised-credential service) implement
// [spi.PasswordHealthChecker] directly; this type intentionally stays
// offline so the SDK adds no network dependency.
type DictionaryPasswordHealthChecker struct {
	weak map[string]struct{}
}

var _ spi.PasswordHealthChecker = (*DictionaryPasswordHealthChecker)(nil)

// DictionaryPasswordHealthConfig configures [NewDictionaryPasswordHealthChecker].
type DictionaryPasswordHealthConfig struct {
	// WeakPasswordFile is an optional path to a newline-delimited file of
	// additional weak passwords to fold into the built-in set. Blank lines
	// and lines starting with '#' are skipped. A read error is returned
	// from the constructor — operator misconfiguration (a missing or
	// unreadable extension file) should be loud at startup, not silently
	// degrade the check to the built-in set only.
	WeakPasswordFile string
}

// NewDictionaryPasswordHealthChecker builds a checker seeded with the
// built-in common-weak-password set, optionally extended with the
// operator-supplied file. A file read error is returned so misconfig
// surfaces at boot rather than silently shrinking coverage.
func NewDictionaryPasswordHealthChecker(cfg DictionaryPasswordHealthConfig) (*DictionaryPasswordHealthChecker, error) {
	weak := make(map[string]struct{}, len(builtinWeakPasswords)+16)
	for _, p := range builtinWeakPasswords {
		weak[p] = struct{}{}
	}
	if cfg.WeakPasswordFile != "" {
		if err := loadWeakPasswordFile(cfg.WeakPasswordFile, weak); err != nil {
			return nil, fmt.Errorf("defaultimpl: load weak password file %q: %w", cfg.WeakPasswordFile, err)
		}
	}
	return &DictionaryPasswordHealthChecker{weak: weak}, nil
}

// Check reports a Weak signal on an exact dictionary match, else (nil, nil).
func (c *DictionaryPasswordHealthChecker) Check(_ context.Context, password string) (*core.CredentialHealth, error) {
	if _, ok := c.weak[password]; ok {
		return &core.CredentialHealth{Weak: true, Reason: reasonWeakDictionary}, nil
	}
	return nil, nil
}

// loadWeakPasswordFile folds a newline-delimited file into dst, skipping
// blank lines and '#'-prefixed comments.
func loadWeakPasswordFile(path string, dst map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dst[line] = struct{}{}
	}
	return sc.Err()
}

// builtinWeakPasswords is a curated set of the most common weak passwords
// drawn from the well-known annual "most common passwords" leak analyses.
// Deliberately inline + bounded (a few hundred entries) rather than a
// multi-thousand-line embed: this is a sane default, and operators extend
// it via WeakPasswordFile. Entries are exact-match (no normalization) so
// case-variants the operator cares about belong in the extension file.
var builtinWeakPasswords = []string{
	"123456", "password", "123456789", "12345678", "12345", "1234567",
	"1234567890", "123123", "111111", "1234", "qwerty", "abc123",
	"000000", "112233", "121212", "654321", "555555", "666666",
	"123321", "1q2w3e4r", "1q2w3e", "qwerty123", "qwertyuiop", "1qaz2wsx",
	"zxcvbnm", "asdfghjkl", "asdfgh", "asdf", "qazwsx", "qwe123",
	"q1w2e3r4", "1qazxsw2", "passw0rd", "password1", "password123",
	"p@ssword", "p@ssw0rd", "admin", "admin123", "root", "toor",
	"letmein", "welcome", "welcome1", "welcome123", "login", "guest",
	"changeme", "default", "secret", "master", "access", "monkey",
	"dragon", "iloveyou", "sunshine", "princess", "football", "baseball",
	"superman", "batman", "trustno1", "starwars", "whatever", "shadow",
	"michael", "jennifer", "jordan", "harley", "ranger", "hunter",
	"buster", "soccer", "hockey", "killer", "george", "andrew",
	"charlie", "thomas", "robert", "daniel", "joshua", "matthew",
	"hello", "hello123", "test", "test123", "testing", "temp",
	"temp123", "demo", "demo123", "abcdef", "abcd1234", "abcd",
	"a1b2c3", "a1b2c3d4", "11111111", "00000000", "987654321", "159753",
	"7777777", "samsung", "google", "facebook", "myspace1", "computer",
	"internet", "service", "freedom", "ginger", "summer", "winter",
	"spring", "autumn", "flower", "purple", "orange", "yellow",
	"silver", "golden", "cookie", "pepper", "chocolate", "banana",
	"cheese", "coffee", "diamond", "rainbow", "nicole", "ashley",
	"amanda", "jessica", "samantha", "michelle", "hannah", "anthony",
	"william", "richard", "mustang", "corvette", "ferrari", "porsche",
	"harley1", "maverick", "phoenix", "tigger", "dakota", "bailey",
	"chelsea", "lovely", "angel", "angels", "killer1", "pokemon",
	"minecraft", "fortnite", "naruto", "zxcvbn", "asdf1234", "qweasd",
	"qweasdzxc", "1234qwer", "passwort", "contraseña", "motdepasse",
	"administrator", "sysadmin", "operator", "manager", "support",
	"oracle", "postgres", "mysql", "redis", "mongodb", "database",
	"server", "system", "network", "security", "firewall", "backup",
	"123456a", "a123456", "abc12345", "12341234", "1212121212",
	"qazwsxedc", "zaq12wsx", "love", "lovers", "iloveu", "password12",
	"trustme", "iforgot", "qwert", "wsxqaz", "lol123", "azerty",
	"azertyuiop", "loveme", "blink182", "metallica", "nirvana", "slipknot",
}
