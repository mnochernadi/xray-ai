package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// setupRefreshDB opens a throwaway panel database and points the service at the
// given subscription body.
func setupRefreshDB(t *testing.T, body string) *InboundSubscriptionService {
	t.Helper()
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	dbtest.InitDB(t, filepath.Join(dbDir, "x-ui.db"))

	svc := NewInboundSubscriptionService()
	svc.fetchOverride = func(context.Context) ([]byte, error) { return []byte(body), nil }
	return svc
}

func managedInbounds(t *testing.T) []*model.Inbound {
	t.Helper()
	all, err := (&InboundService{}).GetAllInbounds()
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	var managed []*model.Inbound
	for _, ib := range all {
		if strings.HasPrefix(ib.Remark, InboundSubscriptionPrefix) {
			managed = append(managed, ib)
		}
	}
	return managed
}

func TestRefreshCreatesManagedInbounds(t *testing.T) {
	body := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@example.com:8443?type=ws&security=tls&host=cdn.example.com&path=%2Fws#Server%20One",
		"trojan://secretpass@example.com:8443?type=ws&security=tls&host=cdn.example.com&path=%2Ft#Server%20Two",
	}, "\n")
	svc := setupRefreshDB(t, body)
	if err := svc.settingService.setString("subInboundSyncDomain", "panel.example.com"); err != nil {
		t.Fatalf("set domain: %v", err)
	}

	result, err := svc.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if result.Added != 2 {
		t.Fatalf("Added = %d, want 2 (skipped: %v)", result.Added, result.Skipped)
	}

	managed := managedInbounds(t)
	if len(managed) != 2 {
		t.Fatalf("managed inbounds = %d, want 2", len(managed))
	}
	// Both links asked for 8443; only one may have it, the other moves to a
	// free TLS fallback port.
	ports := map[int]bool{}
	for _, ib := range managed {
		if ports[ib.Port] {
			t.Fatalf("port %d was assigned twice", ib.Port)
		}
		ports[ib.Port] = true
		// These must reach a subscribing client app, so they are not excluded.
		if ib.ExcludeFromSub {
			t.Errorf("inbound %q should be served in subscription output", ib.Remark)
		}
	}
}

// A client app gets every mirrored inbound from one URL only if all the
// mirrored clients share a subscription id.
func TestRefreshClientsShareSubscriptionId(t *testing.T) {
	body := strings.Join([]string{
		"vless://11111111-2222-3333-4444-555555555555@one.example.com:8080?type=tcp&security=none#One",
		"trojan://secretpass@two.example.com:8081?type=tcp&security=none#Two",
	}, "\n")
	svc := setupRefreshDB(t, body)
	if _, err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	managed := managedInbounds(t)
	if len(managed) != 2 {
		t.Fatalf("managed inbounds = %d, want 2", len(managed))
	}
	subIds := map[string]bool{}
	emails := map[string]bool{}
	for _, ib := range managed {
		var settings struct {
			Clients []struct {
				Email string `json:"email"`
				SubId string `json:"subId"`
			} `json:"clients"`
		}
		if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
			t.Fatalf("settings invalid: %v", err)
		}
		if len(settings.Clients) == 0 {
			t.Fatalf("%s has no clients", ib.Remark)
		}
		subIds[settings.Clients[0].SubId] = true
		if settings.Clients[0].SubId != InboundSubscriptionSubId {
			t.Errorf("%s subId = %q, want %q", ib.Remark, settings.Clients[0].SubId, InboundSubscriptionSubId)
		}
		if emails[settings.Clients[0].Email] {
			t.Errorf("email %q reused across inbounds", settings.Clients[0].Email)
		}
		emails[settings.Clients[0].Email] = true
	}
	if len(subIds) != 1 {
		t.Errorf("clients span %d subscription ids, want 1 shared", len(subIds))
	}
}

// The panel scopes the inbound list by user_id, so a mirrored inbound owned by
// nobody is invisible in the UI even though it runs. It must belong to the
// panel's first (admin) user.
func TestRefreshAssignsInboundsToTheAdminUser(t *testing.T) {
	body := "vless://11111111-2222-3333-4444-555555555555@example.com:8080?type=tcp&security=none#Owned"
	svc := setupRefreshDB(t, body)
	if _, err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	owner := svc.ownerUserId()
	if owner == 0 {
		t.Fatal("ownerUserId returned 0; the inbound would be invisible in the panel")
	}
	for _, ib := range managedInbounds(t) {
		if ib.UserId != owner {
			t.Errorf("inbound %q userId = %d, want %d", ib.Remark, ib.UserId, owner)
		}
	}
}

func TestRefreshReplacesPreviousRun(t *testing.T) {
	first := "vless://11111111-2222-3333-4444-555555555555@example.com:8080?type=tcp&security=none#First"
	svc := setupRefreshDB(t, first)
	if _, err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if got := len(managedInbounds(t)); got != 1 {
		t.Fatalf("after first refresh managed = %d, want 1", got)
	}

	second := "trojan://secretpass@example.com:8081?type=tcp&security=none#Second"
	svc.fetchOverride = func(context.Context) ([]byte, error) { return []byte(second), nil }
	result, err := svc.Refresh(context.Background())
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if result.Removed != 1 || result.Added != 1 {
		t.Fatalf("second refresh removed=%d added=%d, want 1/1", result.Removed, result.Added)
	}

	managed := managedInbounds(t)
	if len(managed) != 1 {
		t.Fatalf("after second refresh managed = %d, want 1", len(managed))
	}
	if !strings.Contains(managed[0].Remark, "Second") {
		t.Errorf("managed inbound = %q, want the second link", managed[0].Remark)
	}
}

func TestRefreshLeavesHandmadeInboundsAlone(t *testing.T) {
	body := "vless://11111111-2222-3333-4444-555555555555@example.com:8080?type=tcp&security=none#Mirrored"
	svc := setupRefreshDB(t, body)

	handmade := &model.Inbound{
		Tag: "handmade-tag", Enable: true, Port: 44444, Protocol: model.VMESS,
		Settings:       `{"clients":[]}`,
		StreamSettings: `{"network":"tcp","security":"none"}`,
		Remark:         "My Own Inbound",
	}
	if _, _, err := (&InboundService{}).AddInbound(handmade); err != nil {
		t.Fatalf("add handmade inbound: %v", err)
	}

	result, err := svc.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if result.Added != 1 {
		t.Fatalf("Added = %d, want 1 (skipped: %v)", result.Added, result.Skipped)
	}

	all, err := (&InboundService{}).GetAllInbounds()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, ib := range all {
		if ib.Remark == "My Own Inbound" {
			found = true
		}
	}
	if !found {
		t.Error("the handmade inbound was removed by the refresh")
	}
	if len(all) != 2 {
		t.Errorf("inbounds = %d, want 2 (handmade + mirrored)", len(all))
	}
}

func TestRefreshRefusesToEmptyThePanel(t *testing.T) {
	body := "vless://11111111-2222-3333-4444-555555555555@example.com:8080?type=tcp&security=none#Keep"
	svc := setupRefreshDB(t, body)
	if _, err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Every REALITY link is unmappable, so the new plan is empty. The existing
	// mirrored inbound must survive rather than the panel losing its setup.
	reality := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=abc#Only%20Reality"
	svc.fetchOverride = func(context.Context) ([]byte, error) { return []byte(reality), nil }
	result, err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected an error when the new plan is empty")
	}
	if result.Removed != 0 {
		t.Errorf("Removed = %d, want 0", result.Removed)
	}
	if got := len(managedInbounds(t)); got != 1 {
		t.Errorf("managed inbounds = %d, want the untouched 1", got)
	}
}
