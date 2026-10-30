package zoraxy_plugin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type PathRouter struct {
	enableDebugPrint bool
	pathHandlers     map[string]http.Handler
	defaultHandler   http.Handler
}

// NewPathRouter creates a new PathRouter
func NewPathRouter() *PathRouter {
	return &PathRouter{
		enableDebugPrint: false,
		pathHandlers:     make(map[string]http.Handler),
	}
}

// RegisterPathHandler registers a handler for a path
func (p *PathRouter) RegisterPathHandler(path string, handler http.Handler) {
	path = strings.TrimSuffix(path, "/")
	p.pathHandlers[path] = handler
}

// RemovePathHandler removes a handler for a path
func (p *PathRouter) RemovePathHandler(path string) {
	delete(p.pathHandlers, path)
}

// SetDefaultHandler sets the default handler for the router
// This handler will be called if no path handler is found
func (p *PathRouter) SetDefaultHandler(handler http.Handler) {
	p.defaultHandler = handler
}

// SetDebugPrintMode sets the debug print mode
func (p *PathRouter) SetDebugPrintMode(enable bool) {
	p.enableDebugPrint = enable
}

// StartStaticCapture starts the static capture ingress
func (p *PathRouter) RegisterStaticCaptureHandle(capture_ingress string, mux *http.ServeMux) {
	if !strings.HasSuffix(capture_ingress, "/") {
		capture_ingress = capture_ingress + "/"
	}
	mux.Handle(capture_ingress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.staticCaptureServeHTTP(w, r)
	}))
}

// staticCaptureServeHTTP serves the static capture path using user defined handler
func (p *PathRouter) staticCaptureServeHTTP(w http.ResponseWriter, r *http.Request) {
	capturePath := r.Header.Get("X-Zoraxy-Capture")
	if capturePath != "" {
		if p.enableDebugPrint {
			fmt.Println("Static capture selected")
		}
		originalURI := r.Header.Get("X-Zoraxy-Uri")
		parsed, err := url.ParseRequestURI(originalURI)
		if err != nil {
			http.Error(w, "Invalid request URI", http.StatusBadRequest)
			return
		}
		r.URL, r.RequestURI = parsed, originalURI
		if handler, ok := p.pathHandlers[capturePath]; ok {
			handler.ServeHTTP(w, r)
			return
		}
	}
	if p.defaultHandler == nil {
		http.NotFound(w, r)
		return
	}
	p.defaultHandler.ServeHTTP(w, r)
}

func (p *PathRouter) PrintRequestDebugMessage(r *http.Request) {
	if p.enableDebugPrint && r != nil {
		fmt.Println("Plugin request received")
	}
}
