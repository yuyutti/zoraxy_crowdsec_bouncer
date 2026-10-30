package zoraxy_plugin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSniffMalformedPayloadCaptures(t *testing.T) {
	router := NewPathRouter()
	mux := http.NewServeMux()
	called := false
	router.RegisterDynamicSniffHandler("/sniff", mux, func(r *DynamicSniffForwardRequest) SniffResult { called = true; return SniffResultSkip })
	for _, payload := range []string{"{", "null", strings.Repeat("x", (1<<20)+1)} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/sniff/", strings.NewReader(payload)))
		if w.Code != 200 || called {
			t.Fatal("invalid payload did not select capture")
		}
	}
}
func TestCapturePreservesURIAndNilDefault(t *testing.T) {
	router := NewPathRouter()
	mux := http.NewServeMux()
	router.RegisterDynamicCaptureHandle("/capture", mux, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/path?url=https://example.com//a&value=a%2Fb" || r.URL.RawQuery != "url=https://example.com//a&value=a%2Fb" {
			t.Errorf("URI changed: %s", r.RequestURI)
		}
	})
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/capture/path?url=https://example.com//a&value=a%2Fb", nil))
	w := httptest.NewRecorder()
	router.staticCaptureServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	if EncodeForwardRequestPayload(nil).ClientIP != "" {
		t.Fatal("nil encoding")
	}
	r := httptest.NewRequest("GET", "/", nil)
	encoded := EncodeForwardRequestPayload(r, "192.0.2.1")
	if encoded.ClientIP != "192.0.2.1" {
		t.Fatal("resolved IP missing")
	}
}
func TestDebugRouterRootAndSymlink(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "www")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "index.html"), []byte("ok {{.csrfToken}}"), 0600)
	os.WriteFile(filepath.Join(dir, "secret.html"), []byte("outside-root"), 0600)
	router := NewPluginFileSystemUIRouter("test", root, "/ui")
	r := httptest.NewRequest("GET", "/ui/", nil)
	r.Header.Set("X-Zoraxy-Csrf", `\"><script>`)
	w := httptest.NewRecorder()
	router.Handler().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("root or token escaping failed")
	}
	w = httptest.NewRecorder()
	router.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/ui/../secret.html", nil))
	if w.Code == 200 {
		t.Fatal("root traversal")
	}
	t.Chdir(dir)
	router.TargetDir = "www"
	w = httptest.NewRecorder()
	router.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/ui/", nil))
	if w.Code != 200 {
		t.Fatal("relative root")
	}
	router.TargetDir = root
	if err := os.Symlink(filepath.Join(dir, "secret.html"), filepath.Join(root, "escape.html")); err != nil {
		t.Log("symlink creation unavailable on this host:", err)
		return
	}
	w = httptest.NewRecorder()
	router.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/ui/escape.html", nil))
	if w.Code == 200 {
		t.Fatal("symlink escaped root")
	}
}
func FuzzSniffPayload(f *testing.F) {
	f.Add([]byte(`{"remote_addr":"192.0.2.1","client_ip":"192.0.2.1"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, payload []byte) { _, _ = DecodeForwardRequestPayload(payload) })
}
