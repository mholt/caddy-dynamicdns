package dynamicdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSimpleHTTPTimeout verifies that a lookup gives up on an endpoint that
// accepts the request and then stalls, before or after sending the headers,
// instead of blocking the check for good.
func TestSimpleHTTPTimeout(t *testing.T) {
	old := simpleHTTPTimeout
	simpleHTTPTimeout = 200 * time.Millisecond
	t.Cleanup(func() { simpleHTTPTimeout = old })

	for _, tc := range []struct {
		name        string
		sendHeaders bool
	}{
		{"stall before headers", false},
		{"stall in body", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.sendHeaders {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("192.0"))
					w.(http.Flusher).Flush()
				}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(release) })

			sh := SimpleHTTP{}
			done := make(chan error, 1)
			go func() {
				_, err := sh.lookupIP(context.Background(), sh.makeClient("tcp4"), srv.URL)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("lookup of a stalled endpoint returned no error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("lookup of a stalled endpoint did not time out")
			}
		})
	}
}
