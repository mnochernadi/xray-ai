package service

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/link"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
)

// maxInboundSubscriptionBytes caps a single inbound subscription response.
const maxInboundSubscriptionBytes int64 = 8 << 20

// InboundSubscriptionPrefix marks the inbounds this feature owns. Every refresh
// deletes inbounds carrying it and recreates them, so a remark is how the
// operator tells a mirrored inbound from one they created by hand.
const InboundSubscriptionPrefix = "[SUB-SYNC] "

// InboundSubscriptionSubId is the shared subscription id every mirrored client
// carries. Fetching <subPath>/<InboundSubscriptionSubId> returns one
// subscription containing every mirrored inbound, which is how a single client
// app gets the whole mirrored set.
const InboundSubscriptionSubId = "subsync-all"

// inboundSubscriptionTLSFallbackPorts and its plain counterpart are the ports a
// mirrored inbound falls back to when the port from the share link is already
// taken on this host. The share link's port belongs to the upstream server, not
// to this one, so it routinely collides with an inbound or with the panel.
var (
	inboundSubscriptionTLSFallbackPorts   = []int{443, 2053, 2083, 2087, 2096, 8443}
	inboundSubscriptionPlainFallbackPorts = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}
)

// InboundSubscriptionService mirrors a remote share-link subscription into
// local inbounds so the panel's own clients can use those servers.
type InboundSubscriptionService struct {
	settingService SettingService
	// fetchOverride lets tests supply a subscription body without a live
	// upstream; it is nil in production.
	fetchOverride func(context.Context) ([]byte, error)
}

func NewInboundSubscriptionService() *InboundSubscriptionService {
	return &InboundSubscriptionService{}
}

// InboundSubscriptionResult reports what one refresh did.
type InboundSubscriptionResult struct {
	Added   int
	Removed int
	Skipped []string
}

func (s *InboundSubscriptionService) getSetting(key string) string {
	value, err := s.settingService.getString(key)
	if err != nil {
		return ""
	}
	return value
}

func (s *InboundSubscriptionService) Enabled() bool {
	return s.getSetting("subInboundSyncEnable") == "true"
}

func (s *InboundSubscriptionService) SubURL() string {
	return strings.TrimSpace(s.getSetting("subInboundSyncUrl"))
}

// fetchSubscription downloads the subscription body.
func (s *InboundSubscriptionService) fetchSubscription(ctx context.Context) ([]byte, error) {
	if s.fetchOverride != nil {
		return s.fetchOverride(ctx)
	}
	url := s.SubURL()
	if url == "" {
		return nil, errors.New("inbound subscription URL is not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "3x-ui-inbound-sub/1.0")
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: netsafe.SSRFGuardedDialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInboundSubscriptionBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxInboundSubscriptionBytes {
		return nil, fmt.Errorf("subscription body exceeds %d bytes", maxInboundSubscriptionBytes)
	}
	return body, nil
}

// planEntry is one inbound to create, resolved from a share link.
type planEntry struct {
	Remark         string
	Protocol       model.Protocol
	Port           int
	Settings       string
	StreamSettings string
	HasTLS         bool
}

// subsyncClient builds the client entry for a mirrored inbound's settings.
// enable/expiryTime/totalGB must be present: the panel reads them when it
// renders the Xray config and treats a missing enable as disabled, which drops
// the client from the running config and blanks the inbound.
//
// subId is what makes the panel serve these clients as one subscription: every
// mirrored client shares InboundSubscriptionSubId, so the single
// <subPath>/<subId> URL returns every inbound at once. Emails stay unique per
// link because the panel rejects a duplicate email across inbounds.
func subsyncClient(fields map[string]any) map[string]any {
	client := map[string]any{
		"email":      "",
		"enable":     true,
		"expiryTime": 0,
		"totalGB":    0,
		"limitIp":    0,
		"subId":      InboundSubscriptionSubId,
	}
	for k, v := range fields {
		client[k] = v
	}
	return client
}

// outboundToInbound converts a parsed share link (an xray outbound) into the
// inbound shape this panel stores. Some fields cannot survive the trip: a TLS
// outbound carries only the client's verification settings, so the server-side
// certificate has to come from the operator's domain (see applyDomainToStream).
func outboundToInbound(ob link.Outbound, domain, identity string) (*planEntry, error) {
	protocol, _ := ob["protocol"].(string)
	remark, _ := ob["tag"].(string)
	if remark == "" {
		remark = "subscription"
	}
	settings, _ := ob["settings"].(map[string]any)
	stream, _ := ob["streamSettings"].(map[string]any)

	entry := &planEntry{Remark: remark}
	var port any
	switch protocol {
	case "vless":
		id, _ := settings["id"].(string)
		if id == "" {
			return nil, errors.New("vless link has no id")
		}
		port = settings["port"]
		flow, _ := settings["flow"].(string)
		entry.Protocol = model.VLESS
		entry.Settings = subsyncJSON(map[string]any{
			"clients":    []any{subsyncClient(map[string]any{"id": id, "flow": flow, "email": clientEmail(identity)})},
			"decryption": "none",
			"fallbacks":  []any{},
		})
	case "vmess":
		id, security := "", "auto"
		if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 {
			if server, ok := vnext[0].(map[string]any); ok {
				port = server["port"]
				if users, ok := server["users"].([]any); ok && len(users) > 0 {
					if user, ok := users[0].(map[string]any); ok {
						id, _ = user["id"].(string)
						if s, ok := user["security"].(string); ok && s != "" {
							security = s
						}
					}
				}
			}
		}
		if id == "" {
			return nil, errors.New("vmess link has no id")
		}
		entry.Protocol = model.VMESS
		entry.Settings = subsyncJSON(map[string]any{
			"clients": []any{subsyncClient(map[string]any{"id": id, "security": security, "email": clientEmail(identity)})},
		})
	case "trojan":
		server, _ := firstServer(settings)
		password, _ := server["password"].(string)
		port = server["port"]
		if password == "" {
			return nil, errors.New("trojan link has no password")
		}
		entry.Protocol = model.Trojan
		entry.Settings = subsyncJSON(map[string]any{
			"clients":   []any{subsyncClient(map[string]any{"password": password, "email": clientEmail(identity)})},
			"fallbacks": []any{},
		})
	case "shadowsocks":
		server, _ := firstServer(settings)
		method, _ := server["method"].(string)
		password, _ := server["password"].(string)
		port = server["port"]
		if method == "" || password == "" {
			return nil, errors.New("shadowsocks link is missing method or password")
		}
		entry.Protocol = model.Shadowsocks
		// Shadowsocks keeps method/password on the inbound, but the client entry
		// still has to exist: the link generator resolves a client per subscriber
		// through it, and without one the inbound yields no subscription link.
		entry.Settings = subsyncJSON(map[string]any{
			"method":   method,
			"password": password,
			"network":  "tcp,udp",
			"clients":  []any{subsyncClient(map[string]any{"email": clientEmail(identity), "password": password})},
		})
	default:
		return nil, fmt.Errorf("protocol %q cannot be mirrored as an inbound", protocol)
	}

	entry.Port = toInt(port)
	if entry.Port <= 0 || entry.Port > 65535 {
		return nil, errors.New("link has an unusable port")
	}

	security, _ := stream["security"].(string)
	if security == "reality" {
		// A share link carries only the REALITY public key and short id; the
		// private key that an inbound needs is never distributed in a link.
		return nil, errors.New("REALITY inbound needs the private key, which the link does not carry")
	}
	entry.HasTLS = security == "tls"
	if entry.HasTLS {
		// Without a domain there is no certificate to serve, and xray refuses
		// to start with a TLS inbound whose certificate is missing.
		if domain == "" {
			return nil, errors.New("TLS inbound needs a domain (set one in the subscription sync settings)")
		}
		stream["tlsSettings"] = map[string]any{
			"serverName": domain,
			"certificates": []any{map[string]any{
				"certificateFile": "/root/cert/" + domain + "/fullchain.pem",
				"keyFile":         "/root/cert/" + domain + "/privkey.pem",
			}},
		}
	} else if security == "none" || security == "" {
		// Server-side stream settings must not carry a client's TLS verification
		// fields, so drop the ones the parser filled in.
		delete(stream, "tlsSettings")
		delete(stream, "realitySettings")
	} else {
		return nil, fmt.Errorf("security %q is not supported for an inbound", security)
	}
	clearInboundHost(stream)
	entry.StreamSettings = subsyncJSON(stream)
	return entry, nil
}

// clearInboundHost blanks the Host a share link asked the inbound to require.
//
// A share link's host belongs to the upstream provider's CDN, not to this
// server: the link carries it so the *client* sends it, and the mirrored
// inbound then rejected every connection whose Host differed. Blanking it makes
// Xray accept any Host, which is what lets one inbound serve both the direct
// address and a Cloudflare-proxied one without a second inbound or an Origin
// Rule (Host override is Enterprise-only on Cloudflare).
func clearInboundHost(stream map[string]any) {
	for _, key := range []string{"wsSettings", "httpupgradeSettings", "xhttpSettings"} {
		cfg, ok := stream[key].(map[string]any)
		if !ok {
			continue
		}
		delete(cfg, "host")
		if headers, ok := cfg["headers"].(map[string]any); ok {
			for name := range headers {
				if strings.EqualFold(name, "host") {
					delete(headers, name)
				}
			}
		}
	}
}

// firstServer returns the first entry of a link's servers/vnext array. Trojan
// and shadowsocks put their credentials in a nested server object while vless
// keeps them flat on settings, so this covers the nested shape only.
func firstServer(settings map[string]any) (map[string]any, bool) {
	servers, ok := settings["servers"].([]any)
	if !ok || len(servers) == 0 {
		return nil, false
	}
	server, ok := servers[0].(map[string]any)
	return server, ok
}

// clientEmail derives a stable, unique client email from a link's identity.
// It hashes the whole link rather than the credential alone: several links in
// one subscription routinely share a UUID, and the panel rejects duplicate
// emails across inbounds.
func clientEmail(identity string) string {
	sum := sha1.Sum([]byte(identity))
	return "subsync-" + hex.EncodeToString(sum[:])[:10]
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case string:
		var out int
		_, _ = fmt.Sscanf(n, "%d", &out)
		return out
	}
	return 0
}

func subsyncJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// buildPlan turns a subscription body into the inbounds that should exist now.
func (s *InboundSubscriptionService) buildPlan(body []byte, domain string) ([]*planEntry, []string) {
	outbounds, identities, err := link.ParseSubscriptionBody(body)
	if err != nil {
		return nil, []string{fmt.Sprintf("could not parse subscription: %v", err)}
	}

	var plan []*planEntry
	var skipped []string
	seen := map[string]bool{}
	for i, ob := range outbounds {
		identity := identities[i]
		entry, err := outboundToInbound(ob, domain, identity)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", entryRemark(ob), err))
			continue
		}
		key := fmt.Sprintf("%s|%d|%s", entry.Protocol, entry.Port, entry.Remark)
		if seen[key] {
			continue
		}
		seen[key] = true
		plan = append(plan, entry)
	}
	return plan, skipped
}

func entryRemark(ob link.Outbound) string {
	if remark, ok := ob["tag"].(string); ok && remark != "" {
		return remark
	}
	if protocol, ok := ob["protocol"].(string); ok {
		return protocol
	}
	return "link"
}

// Refresh fetches the subscription and reconciles the mirrored inbounds.
func (s *InboundSubscriptionService) Refresh(ctx context.Context) (*InboundSubscriptionResult, error) {
	result := &InboundSubscriptionResult{}
	body, err := s.fetchSubscription(ctx)
	if err != nil {
		return result, err
	}

	domain := strings.TrimSpace(s.getSetting("subInboundSyncDomain"))
	plan, skipped := s.buildPlan(body, domain)
	result.Skipped = skipped

	inboundService := &InboundService{}

	existing, err := inboundService.GetAllInbounds()
	if err != nil {
		return result, err
	}
	// Ports held by inbounds the operator made by hand: the mirrored ones are
	// about to be deleted, so they do not reserve their own port.
	usedPorts := map[int]bool{}
	var managedIds []int
	for _, ib := range existing {
		if strings.HasPrefix(ib.Remark, InboundSubscriptionPrefix) {
			managedIds = append(managedIds, ib.Id)
			continue
		}
		usedPorts[ib.Port] = true
	}
	if panelPort, err := s.settingService.GetPort(); err == nil {
		usedPorts[panelPort] = true
	}
	// The subscription listener is the panel's own; a mirrored inbound on that
	// port takes it from the panel, and then the whole Xray config fails to bind
	// and every inbound stops, not just the one that collided.
	if subPort, err := s.settingService.GetSubPort(); err == nil && subPort > 0 {
		usedPorts[subPort] = true
	}

	// Build the replacement set before touching the panel: a subscription that
	// parses to nothing must not leave the operator with no inbounds at all.
	type plannedAdd struct {
		entry *planEntry
		port  int
	}
	var adds []plannedAdd
	for _, entry := range plan {
		port := entry.Port
		if usedPorts[port] {
			port = 0
			pool := inboundSubscriptionPlainFallbackPorts
			if entry.HasTLS {
				pool = inboundSubscriptionTLSFallbackPorts
			}
			for _, candidate := range pool {
				if !usedPorts[candidate] {
					port = candidate
					break
				}
			}
			if port == 0 {
				result.Skipped = append(result.Skipped, fmt.Sprintf("%s: port %d is taken and no fallback port is free", entry.Remark, entry.Port))
				continue
			}
		}
		usedPorts[port] = true
		adds = append(adds, plannedAdd{entry: entry, port: port})
	}

	// Nothing to replace them with: deleting here would leave the panel with no
	// mirrored inbounds at all because the subscription went unparseable or used
	// only unmappable links (REALITY, or TLS without a certificate).
	if len(adds) == 0 && len(managedIds) > 0 {
		return result, fmt.Errorf("the subscription produced no usable inbounds; keeping the %d existing ones", len(managedIds))
	}

	if len(managedIds) > 0 {
		deleted, _, delErr := inboundService.DelInbounds(managedIds)
		if delErr != nil {
			return result, fmt.Errorf("could not remove old mirrored inbounds: %w", delErr)
		}
		result.Removed = deleted.Deleted
	}

	// The mirrored inbounds are meant to be handed back out: a client app
	// fetches <subPath>/<InboundSubscriptionSubId> and gets every one of them.
	ownerId := s.ownerUserId()
	for _, add := range adds {
		inbound := &model.Inbound{
			UserId:         ownerId,
			Remark:         InboundSubscriptionPrefix + add.entry.Remark,
			Enable:         true,
			Port:           add.port,
			Protocol:       add.entry.Protocol,
			Settings:       add.entry.Settings,
			StreamSettings: add.entry.StreamSettings,
			Sniffing:       subsyncJSON(map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}}),
		}
		if _, _, err := inboundService.AddInbound(inbound); err != nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: %v", add.entry.Remark, err))
			continue
		}
		result.Added++
	}
	return result, nil
}

// ownerUserId is the panel user the mirrored inbounds belong to. The inbound
// list is scoped by user_id, so a row owned by nobody (0) is invisible in the
// panel even though it exists and runs. There is no request session on a cron
// run, so attribute to the first (admin) user, matching node sync.
func (s *InboundSubscriptionService) ownerUserId() int {
	var user model.User
	if err := database.GetDB().Model(model.User{}).Order("id asc").First(&user).Error; err == nil {
		return user.Id
	}
	return 1
}

// RunScheduledRefresh is the cron entry point.
func (s *InboundSubscriptionService) RunScheduledRefresh() {
	if !s.Enabled() {
		return
	}
	result, err := s.Refresh(context.Background())
	if err != nil {
		logger.Warning("inbound subscription sync failed:", err)
		return
	}
	logger.Infof("inbound subscription sync: added %d, removed %d, skipped %d", result.Added, result.Removed, len(result.Skipped))
}
