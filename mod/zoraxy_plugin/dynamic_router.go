package zoraxy_plugin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

/*

	Dynamic Path Handler

*/

type SniffResult int

const (
	SniffResultAccept SniffResult = iota // Forward the request to this plugin dynamic capture ingress
	SniffResultSkip                      // Skip this plugin and let the next plugin handle the request
)

type SniffHandler func(*DynamicSniffForwardRequest) SniffResult

/*
RegisterDynamicSniffHandler registers a dynamic sniff handler for a path
You can decide to accept or skip the request based on the request header and paths
*/
func (p *PathRouter) RegisterDynamicSniffHandler(sniff_ingress string, mux *http.ServeMux, handler SniffHandler) {
	if !strings.HasSuffix(sniff_ingress, "/") {
		sniff_ingress = sniff_ingress + "/"
	}
	mux.Handle(sniff_ingress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Decode the request payload
		jsonBytes, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(jsonBytes) > 1<<20 {
			// Sniff's only capture signal is 200. HTTP errors may fail open in
			// Zoraxy, so malformed/oversized internal payloads select capture.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		payload, err := DecodeForwardRequestPayload(jsonBytes)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}

		// Get the forwarded request UUID
		forwardUUID := r.Header.Get("X-Zoraxy-RequestID")
		payload.requestUUID = forwardUUID
		payload.rawRequest = r

		sniffResult := handler(&payload)
		if sniffResult == SniffResultAccept {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte("SKIP"))
		}
	}))
}

// RegisterDynamicCaptureHandle register the dynamic capture ingress path with a handler
func (p *PathRouter) RegisterDynamicCaptureHandle(capture_ingress string, mux *http.ServeMux, handlefunc func(http.ResponseWriter, *http.Request)) {
	if !strings.HasSuffix(capture_ingress, "/") {
		capture_ingress = capture_ingress + "/"
	}
	mux.Handle(capture_ingress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		rewrittenURL := r.RequestURI
		rewrittenURL = strings.TrimPrefix(rewrittenURL, capture_ingress)
		if rewrittenURL == "" {
			rewrittenURL = "/"
		}
		if !strings.HasPrefix(rewrittenURL, "/") {
			rewrittenURL = "/" + rewrittenURL
		}
		parsed, err := url.ParseRequestURI(rewrittenURL)
		if err != nil {
			http.Error(w, "Invalid request URI", http.StatusBadRequest)
			return
		}
		r.RequestURI, r.URL = rewrittenURL, parsed

		handlefunc(w, r)
	}))
}

/*
	Sniffing and forwarding

	The following functions are here to help with
	sniffing and forwarding requests to the dynamic
	router.
*/
// A custom request object to be used in the dynamic sniffing
type DynamicSniffForwardRequest struct {
	Method     string              `json:"method"`
	Hostname   string              `json:"hostname"`
	URL        string              `json:"url"`
	Header     map[string][]string `json:"header"`
	ClientIP   string              `json:"client_ip"`
	RemoteAddr string              `json:"remote_addr"`
	Host       string              `json:"host"`
	RequestURI string              `json:"request_uri"`
	Proto      string              `json:"proto"`
	ProtoMajor int                 `json:"proto_major"`
	ProtoMinor int                 `json:"proto_minor"`

	/* Internal use */
	rawRequest  *http.Request `json:"-"`
	requestUUID string        `json:"-"`
}

// GetForwardRequestPayload returns a DynamicSniffForwardRequest object from an http.Request object
func EncodeForwardRequestPayload(r *http.Request, clientIP ...string) DynamicSniffForwardRequest {
	if r == nil {
		return DynamicSniffForwardRequest{}
	}
	resolved := ""
	if len(clientIP) > 0 {
		resolved = clientIP[0]
	}
	return DynamicSniffForwardRequest{
		ClientIP:   resolved,
		Method:     r.Method,
		Hostname:   r.Host,
		URL:        r.URL.String(),
		Header:     r.Header,
		RemoteAddr: r.RemoteAddr,
		Host:       r.Host,
		RequestURI: r.RequestURI,
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		rawRequest: r,
	}
}

// DecodeForwardRequestPayload decodes JSON bytes into a DynamicSniffForwardRequest object
func DecodeForwardRequestPayload(jsonBytes []byte) (DynamicSniffForwardRequest, error) {
	var payload DynamicSniffForwardRequest
	if len(jsonBytes) > 1<<20 || strings.TrimSpace(string(jsonBytes)) == "null" {
		return payload, errors.New("invalid sniff payload")
	}
	err := json.Unmarshal(jsonBytes, &payload)
	if err != nil {
		return DynamicSniffForwardRequest{}, err
	}
	return payload, nil
}

// GetRequest returns the original http.Request object, for debugging purposes
func (dsfr *DynamicSniffForwardRequest) GetRequest() *http.Request {
	if dsfr == nil {
		return nil
	}
	return dsfr.rawRequest
}

// GetRequestUUID returns the request UUID
// if this UUID is empty string, that might indicate the request
// is not coming from the dynamic router
func (dsfr *DynamicSniffForwardRequest) GetRequestUUID() string {
	if dsfr == nil {
		return ""
	}
	return dsfr.requestUUID
}
