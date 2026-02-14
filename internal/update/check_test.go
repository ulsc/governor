package update

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewerVersionAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0"}`))
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "v0.2.0" {
		t.Fatalf("expected NewVersion=v0.2.0, got %q", r.NewVersion)
	}
}

func TestSameVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.1.0"}`))
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion, got %q", r.NewVersion)
	}
}

func TestOlderOnServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.0.9"}`))
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion, got %q", r.NewVersion)
	}
}

func TestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion on server error, got %q", r.NewVersion)
	}
}

func TestInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion on invalid JSON, got %q", r.NewVersion)
	}
}

func TestEmptyTagName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":""}`))
	}))
	defer srv.Close()

	r := checkURL(srv.URL, "v0.1.0")
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion on empty tag, got %q", r.NewVersion)
	}
}

func TestNetworkTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	start := time.Now()
	r := checkURL(srv.URL, "v0.1.0")
	elapsed := time.Since(start)

	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion on timeout, got %q", r.NewVersion)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("expected timeout within ~3s, took %v", elapsed)
	}
}

func TestDevVersionSkips(t *testing.T) {
	// checkURL with "dev" as current: any tag will be lexicographically
	// greater than "dev" (v > d), so we verify CheckAsync short-circuits.
	// We test that by confirming checkURL("dev") would return a result but
	// CheckAsync skips it entirely when version.Version == "dev".
	// Since version.Version defaults to "dev" in tests, CheckAsync should
	// return an empty result without making any HTTP call.
	ch := CheckAsync()
	r := <-ch
	if r.NewVersion != "" {
		t.Fatalf("expected empty NewVersion for dev build, got %q", r.NewVersion)
	}
}

func TestPrintNoticeNoUpdate(t *testing.T) {
	printed := PrintNotice(Result{})
	if printed {
		t.Fatal("expected PrintNotice to return false for empty result")
	}
}

func TestPrintNoticeWithUpdate(t *testing.T) {
	printed := PrintNotice(Result{NewVersion: "v0.2.0"})
	if !printed {
		t.Fatal("expected PrintNotice to return true for available update")
	}
}
