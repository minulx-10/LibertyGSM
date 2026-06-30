package doh

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolve(t *testing.T) {
	want := []byte{0xab, 0xcd, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != mimeDNS {
			t.Errorf("Content-Type = %q, want %q", ct, mimeDNS)
		}
		if body, _ := io.ReadAll(r.Body); len(body) == 0 {
			t.Error("query body is empty")
		}
		w.Header().Set("Content-Type", mimeDNS)
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	c := New([]string{srv.URL})
	got, err := c.Resolve([]byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Resolve = %x, want %x", got, want)
	}
}

func TestResolveFailover(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte{0x01, 0x02, 0x03})
	}))
	defer good.Close()

	c := New([]string{bad.URL, good.URL})
	got, err := c.Resolve([]byte{0x00, 0x00})
	if err != nil {
		t.Fatalf("failover Resolve: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("failover returned empty response")
	}
	// The active endpoint should now be the good one.
	if _, url := c.activeEndpoint(); url != good.URL {
		t.Errorf("active endpoint = %s, want %s", url, good.URL)
	}
}

func TestResolveAllFail(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()

	c := New([]string{bad.URL})
	if _, err := c.Resolve([]byte{0x00, 0x00}); err == nil {
		t.Fatal("expected an error when all endpoints fail")
	}
}
