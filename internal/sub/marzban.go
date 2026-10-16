package sub

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// MarzbanSubId resolves a Marzban subscription token to the username it names.
//
// Marzban serves subscriptions at <prefix>/sub/<token>, where the token is
// base64url("username,timestamp") followed by the first ten characters of a
// SHA-256 over that payload plus the panel's secret. The timestamp changes on
// every call, so the same user holds a different-looking URL each time — but
// the signature is what Marzban checks, and it never expires.
//
// Accepting the token here means a user moved from a Marzban panel keeps the
// exact subscription URL they already have: only the host part changes, and the
// mirrored clients carry the username as their subId.
func (s *SubService) MarzbanSubId(token string) (string, bool) {
	secret := ""
	if v, err := s.settingService.GetMarzbanSubSecret(); err == nil {
		secret = strings.TrimSpace(v)
	}
	// A token is at least a short payload plus the ten-character signature.
	if secret == "" || len(token) < 15 {
		return "", false
	}

	payload, signature := token[:len(token)-10], token[len(token)-10:]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(raw), ",", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", false
	}

	sum := sha256.Sum256([]byte(payload + secret))
	if base64.RawURLEncoding.EncodeToString(sum[:])[:10] != signature {
		return "", false
	}
	return parts[0], true
}
