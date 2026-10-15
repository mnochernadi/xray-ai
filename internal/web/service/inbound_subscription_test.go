package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestOutboundToInboundVless(t *testing.T) {
	body := []byte("vless://11111111-2222-3333-4444-555555555555@example.com:8443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com#My%20Server\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
	if len(plan) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(plan))
	}
	entry := plan[0]
	if entry.Protocol != "vless" {
		t.Errorf("protocol = %q, want vless", entry.Protocol)
	}
	if entry.Port != 8443 {
		t.Errorf("port = %d, want 8443", entry.Port)
	}
	if entry.Remark != "My Server" {
		t.Errorf("remark = %q, want %q", entry.Remark, "My Server")
	}
	if !entry.HasTLS {
		t.Error("expected HasTLS")
	}

	var settings struct {
		Clients    []struct{ Id string } `json:"clients"`
		Decryption string                `json:"decryption"`
	}
	if err := json.Unmarshal([]byte(entry.Settings), &settings); err != nil {
		t.Fatalf("settings is not valid JSON: %v", err)
	}
	if settings.Decryption != "none" {
		t.Errorf("decryption = %q, want none", settings.Decryption)
	}
	if len(settings.Clients) != 1 || settings.Clients[0].Id != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("clients = %+v", settings.Clients)
	}

	var stream struct {
		Network     string `json:"network"`
		Security    string `json:"security"`
		TlsSettings struct {
			ServerName   string `json:"serverName"`
			Certificates []struct {
				CertificateFile string `json:"certificateFile"`
				KeyFile         string `json:"keyFile"`
			} `json:"certificates"`
		} `json:"tlsSettings"`
		WsSettings struct {
			Path string `json:"path"`
			Host string `json:"host"`
		} `json:"wsSettings"`
	}
	if err := json.Unmarshal([]byte(entry.StreamSettings), &stream); err != nil {
		t.Fatalf("streamSettings is not valid JSON: %v", err)
	}
	if stream.Network != "ws" {
		t.Errorf("network = %q, want ws", stream.Network)
	}
	if stream.WsSettings.Path != "/ws" || stream.WsSettings.Host != "cdn.example.com" {
		t.Errorf("wsSettings = %+v", stream.WsSettings)
	}
	if stream.TlsSettings.ServerName != "panel.example.com" {
		t.Errorf("serverName = %q, want the panel domain", stream.TlsSettings.ServerName)
	}
	if len(stream.TlsSettings.Certificates) != 1 {
		t.Fatalf("expected a certificate entry, got %d", len(stream.TlsSettings.Certificates))
	}
	if stream.TlsSettings.Certificates[0].CertificateFile != "/root/cert/panel.example.com/fullchain.pem" {
		t.Errorf("certificateFile = %q", stream.TlsSettings.Certificates[0].CertificateFile)
	}
}

func TestOutboundToInboundTLSWithoutDomainIsSkipped(t *testing.T) {
	body := []byte("vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&host=cdn.example.com#Needs%20TLS\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "")
	if len(plan) != 0 {
		t.Fatalf("expected no plan without a domain, got %d", len(plan))
	}
	if len(skipped) != 1 {
		t.Fatalf("expected 1 skip reason, got %v", skipped)
	}
}

func TestOutboundToInboundRealityIsSkipped(t *testing.T) {
	body := []byte("vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=abc&sni=www.example.com#Reality\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(plan) != 0 {
		t.Fatalf("expected REALITY to be skipped, got %d entries", len(plan))
	}
	if len(skipped) != 1 {
		t.Fatalf("expected 1 skip reason, got %v", skipped)
	}
}

func TestOutboundToInboundVmess(t *testing.T) {
	payload := map[string]any{
		"v": "2", "ps": "VMess Server", "add": "example.com", "port": "443",
		"id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "cdn.example.com", "path": "/v", "tls": "",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("vmess://" + base64.StdEncoding.EncodeToString(raw) + "\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
	if len(plan) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(plan))
	}
	if plan[0].Protocol != "vmess" {
		t.Errorf("protocol = %q, want vmess", plan[0].Protocol)
	}
	if plan[0].Port != 443 {
		t.Errorf("port = %d, want 443", plan[0].Port)
	}
	if plan[0].HasTLS {
		t.Error("vmess link without tls should not be marked as TLS")
	}
}

func TestOutboundToInboundTrojan(t *testing.T) {
	body := []byte("trojan://secretpass@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Ft#Trojan\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
	if len(plan) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(plan))
	}
	if plan[0].Protocol != "trojan" {
		t.Errorf("protocol = %q, want trojan", plan[0].Protocol)
	}
	var settings struct {
		Clients []struct {
			Password string `json:"password"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(plan[0].Settings), &settings); err != nil {
		t.Fatalf("settings invalid: %v", err)
	}
	if len(settings.Clients) != 1 || settings.Clients[0].Password != "secretpass" {
		t.Errorf("clients = %+v", settings.Clients)
	}
}

func TestOutboundToInboundShadowsocks(t *testing.T) {
	body := []byte("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#SS%20Server\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
	if len(plan) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(plan))
	}
	if plan[0].Protocol != "shadowsocks" {
		t.Errorf("protocol = %q, want shadowsocks", plan[0].Protocol)
	}
	if plan[0].Port != 8388 {
		t.Errorf("port = %d, want 8388", plan[0].Port)
	}
	var settings struct {
		Method   string `json:"method"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(plan[0].Settings), &settings); err != nil {
		t.Fatalf("settings invalid: %v", err)
	}
	if settings.Method != "aes-256-gcm" || settings.Password != "password" {
		t.Errorf("settings = %+v", settings)
	}
}

func TestBuildPlanDropsDuplicateLinks(t *testing.T) {
	line := "vless://11111111-2222-3333-4444-555555555555@example.com:8080?type=tcp&security=none#Dup\n"
	plan, _ := (&InboundSubscriptionService{}).buildPlan([]byte(line+line), "")
	if len(plan) != 1 {
		t.Fatalf("expected the duplicate to be dropped, got %d entries", len(plan))
	}
}

func TestBuildPlanSkipsUnsupportedProtocol(t *testing.T) {
	body := []byte("hysteria2://pass@example.com:8443/?sni=x#Hy2\n")
	plan, skipped := (&InboundSubscriptionService{}).buildPlan(body, "panel.example.com")
	if len(plan) != 0 {
		t.Fatalf("expected no entries, got %d", len(plan))
	}
	if len(skipped) == 0 {
		t.Error("expected a skip reason for the unsupported protocol")
	}
}
