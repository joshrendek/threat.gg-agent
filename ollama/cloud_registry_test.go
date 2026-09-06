package ollama

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSeptemberCloudRegistrySnapshots(t *testing.T) {
	raw, err := os.ReadFile("testdata/cloud_registry_20260906.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured map[string]struct {
		Config struct {
			RemoteModel  string   `json:"remote_model"`
			Context      int      `json:"context_length"`
			Parameters   string   `json:"model_type"`
			Quantization string   `json:"file_type"`
			Capabilities []string `json:"capabilities"`
		} `json:"config"`
		Digest string         `json:"digest"`
		Size   int64          `json:"size"`
		Show   map[string]any `json:"show"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 8 {
		t.Fatal("incomplete registry capture")
	}
	catalog := newCatalog()
	req := httptest.NewRequest("GET", "/api/tags", nil)
	for name, want := range captured {
		t.Run(name, func(t *testing.T) {
			m, ok := catalog.get(req, name)
			if !ok {
				t.Fatal("verified model absent from catalog")
			}
			if m.Digest != want.Digest || m.Size != want.Size || m.RemoteModel != want.Config.RemoteModel || m.Details.ContextLength != want.Config.Context || m.Details.ParameterSize != want.Config.Parameters || m.Details.QuantizationLevel != want.Config.Quantization || !reflect.DeepEqual(m.Capabilities, want.Config.Capabilities) {
				t.Fatalf("metadata differs from registry: %+v", m)
			}
			if modified, err := time.Parse(time.RFC3339Nano, m.ModifiedAt); err != nil || modified.After(time.Now()) {
				t.Fatal("catalog timestamp is in the future", m.ModifiedAt)
			}
			var show map[string]any
			if err := json.Unmarshal(do(t, "POST", "/api/show", fmt.Sprintf(`{"model":%q}`, name)).Body.Bytes(), &show); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(show, want.Show) {
				t.Fatalf("show differs from hosted response:\ngot %v\nwant %v", show, want.Show)
			}
			for _, path := range []string{"/api/generate", "/v1/chat/completions"} {
				body := fmt.Sprintf(`{"model":%q,"prompt":"Reply with OK","messages":[{"role":"user","content":"Reply with OK"}],"stream":false}`, name)
				if rec := do(t, "POST", path, body); rec.Code != 200 {
					t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
				}
			}
			// Delete/re-pull must restore the captured remote alias and digest and must
			// never remove the base model for a different source address.
			ip := "203.0.113.202"
			body := fmt.Sprintf(`{"model":%q,"stream":false}`, name)
			if rec := doFrom(t, ip, "DELETE", "/api/delete", body); rec.Code != 200 {
				t.Fatal(rec.Code)
			}
			if rec := doFrom(t, ip, "POST", "/api/generate", body); rec.Code != 404 {
				t.Fatal("deleted model still serves")
			}
			if rec := do(t, "POST", "/api/generate", body); rec.Code != 200 {
				t.Fatal("deletion leaked to another source")
			}
			if rec := doFrom(t, ip, "POST", "/api/pull", body); rec.Code != 200 {
				t.Fatal("restore failed", rec.Body.String())
			}
			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = ip + ":54321"
			restored, ok := models.get(request, name)
			if !ok || restored.Digest != want.Digest || restored.RemoteModel != want.Config.RemoteModel {
				t.Fatal("restore lost identity", restored)
			}
		})
	}
	for _, name := range []string{"granite4.2:cloud", "mistral-medium-3.5:cloud", "qwen3.8:cloud", "nemotron3:cloud", "qwen3.6:cloud", "nemotron-3.5-lightning:cloud", "ornith-1.5:cloud", "ornith:cloud", "qwen3.8-flash-next:cloud", "muse-glimmer:cloud", "granite4.1:cloud"} {
		if rec := do(t, "POST", "/api/generate", fmt.Sprintf(`{"model":%q,"prompt":"hi","stream":false}`, name)); rec.Code != 404 {
			t.Errorf("invented model %q accepted", name)
		}
	}
}
