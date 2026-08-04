package selfservice

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestPhysicalDeviceHandlersNilGuardSessionManager(t *testing.T) {
	d := newTestDeps()
	d.sessions = nil
	d.devices = device.NewMemoryStore()
	dev := &device.Device{ID: "device-1", UserID: "user-1", Fingerprint: "fp-1"}
	if err := d.devices.Upsert(t.Context(), dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	ctx, listRec := newCtx(http.MethodGet, "", "")
	HandleMyDevices(d, ctx)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listRec.Code)
	}

	deleteRec := servePath(http.MethodDelete, "/me/devices/:id", "/me/devices/"+dev.ID, "",
		func(ctx core.HandlerContext) { HandleDeleteMyDevice(d, ctx) })
	if deleteRec.Code != http.StatusMultiStatus {
		t.Fatalf("delete status = %d body=%s, want 207", deleteRec.Code, deleteRec.Body.String())
	}
	body := decodeBody(t, deleteRec)
	result, _ := body["result"].(map[string]any)
	sessions, _ := result["sessions"].([]any)
	first, _ := sessions[0].(map[string]any)
	if first["error"] != "session_manager_unavailable" {
		t.Fatalf("partial result = %#v", body)
	}
}
