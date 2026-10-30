package zoraxy_plugin

import (
	"html"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type PluginUiDebugRouter struct {
	PluginID         string //The ID of the plugin
	TargetDir        string //The directory where the UI files are stored
	HandlerPrefix    string //The prefix of the handler used to route this router, e.g. /ui
	EnableDebug      bool   //Enable debug mode
	terminateHandler func() //The handler to be called when the plugin is terminated
}

// NewPluginFileSystemUIRouter creates a new PluginUiRouter with file system
// The targetDir is the directory where the UI files are stored (e.g. ./www)
// The handlerPrefix is the prefix of the handler used to route this router
// The handlerPrefix should start with a slash (e.g. /ui) that matches the http.Handle path
// All prefix should not end with a slash
func NewPluginFileSystemUIRouter(pluginID string, targetDir string, handlerPrefix string) *PluginUiDebugRouter {
	//Make sure all prefix are in /prefix format
	if !strings.HasPrefix(handlerPrefix, "/") {
		handlerPrefix = "/" + handlerPrefix
	}
	handlerPrefix = strings.TrimSuffix(handlerPrefix, "/")

	//Return the PluginUiRouter
	return &PluginUiDebugRouter{
		PluginID:      pluginID,
		TargetDir:     targetDir,
		HandlerPrefix: handlerPrefix,
	}
}

// Handler uses os.Root: relative roots work, and symlinks cannot escape it.
// This router is a development helper, not used by production main.
func (p *PluginUiDebugRouter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := strings.TrimPrefix(r.URL.Path, p.HandlerPrefix)
		for _, part := range strings.Split(requestPath, "/") {
			if part == ".." {
				http.Error(w, "Invalid file path", http.StatusBadRequest)
				return
			}
		}
		root, err := os.OpenRoot(p.TargetDir)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer root.Close()
		name := strings.TrimPrefix(path.Clean("/"+requestPath), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		file, err := root.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil || !stat.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".html") {
			body, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
			if err != nil || len(body) > 2<<20 {
				http.Error(w, "UI file too large", http.StatusInternalServerError)
				return
			}
			token := html.EscapeString(r.Header.Get("X-Zoraxy-Csrf"))
			body = []byte(strings.ReplaceAll(string(body), "{{.csrfToken}}", token))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodHead {
				_, _ = w.Write(body)
			}
			return
		}
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), file)
	})
}

// RegisterTerminateHandler registers the terminate handler for the PluginUiRouter
// The terminate handler will be called when the plugin is terminated from Zoraxy plugin manager
// if mux is nil, the handler will be registered to http.DefaultServeMux
func (p *PluginUiDebugRouter) RegisterTerminateHandler(termFunc func(), mux *http.ServeMux) {
	p.terminateHandler = termFunc
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc(p.HandlerPrefix+"/term", func(w http.ResponseWriter, r *http.Request) {
		p.terminateHandler()
		w.WriteHeader(http.StatusOK)
		go func() {
			//Make sure the response is sent before the plugin is terminated
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}()
	})
}

// Attach the file system UI handler to the target http.ServeMux
func (p *PluginUiDebugRouter) AttachHandlerToMux(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}

	p.HandlerPrefix = strings.TrimSuffix(p.HandlerPrefix, "/")
	mux.Handle(p.HandlerPrefix+"/", p.Handler())
}
