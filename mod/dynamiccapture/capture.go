package dynamiccapture

import (
	"fmt"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const maxPageBytes = 256 << 10

// NewBlockHandler loads administrator-authored static HTML once. No request data
// is interpolated. A load error returns a blocking fallback AND an error.
func NewBlockHandler(cfg config.BlockResponseConfig, configPath string) (http.Handler, error) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { CaptureHandler(nil, w, r) })
	if err := cfg.Validate(); err != nil {
		return fallback, err
	}
	body, contentType := []byte("Forbidden"), "text/plain; charset=utf-8"
	if cfg.Page == "evil" {
		body = []byte(fmt.Sprintf(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>666 Evil</title><style>body{background:#141018;color:#f9edf2;font:20px system-ui;text-align:center;padding:12vh 1rem}h1{font-size:4rem;color:#fa697e}</style><h1>666 Evil</h1><p>I'm a teapot. You are evil.<br>I refuse to serve you.</p><p>HTTP %d</p></html>`, cfg.StatusCode))
		contentType = "text/html; charset=utf-8"
	} else if cfg.Page == "custom" {
		path := cfg.CustomPage
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(configPath), path)
		}
		file, err := os.Open(path)
		if err != nil {
			return fallback, fmt.Errorf("unable to open custom block page")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxPageBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > maxPageBytes || !utf8.Valid(data) {
			return fallback, fmt.Errorf("custom block page unreadable or exceeds 256 KiB")
		}
		body, contentType = data, "text/html; charset=utf-8"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(cfg.StatusCode)
		if r == nil || r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}), nil
}

func CaptureHandler(_ *logrus.Logger, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	if r == nil || r.Method != http.MethodHead {
		_, _ = w.Write([]byte("Forbidden"))
	}
}
