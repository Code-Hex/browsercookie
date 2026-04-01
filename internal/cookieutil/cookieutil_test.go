package cookieutil

import (
	"net/http"
	"testing"
)

func TestFilterByDomainsMatchesExactAndSuffixCaseInsensitively(t *testing.T) {
	t.Parallel()

	cookies := []*http.Cookie{
		{Name: "root", Domain: ".example.com"},
		{Name: "sub", Domain: "api.example.com"},
		{Name: "other", Domain: ".example.org"},
	}

	filtered := FilterByDomains(cookies, []string{"EXAMPLE.com"})
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2", len(filtered))
	}
	if filtered[0].Name != "root" || filtered[1].Name != "sub" {
		t.Fatalf("filtered = %#v", filtered)
	}
}

func TestFilterByDomainsIgnoresParentDomainMismatch(t *testing.T) {
	t.Parallel()

	cookies := []*http.Cookie{
		{Name: "parent", Domain: ".example.com"},
		{Name: "child", Domain: ".child.example.com"},
	}

	filtered := FilterByDomains(cookies, []string{"child.example.com"})
	if len(filtered) != 1 {
		t.Fatalf("len(filtered) = %d, want 1", len(filtered))
	}
	if filtered[0].Name != "child" {
		t.Fatalf("filtered cookie = %#v", filtered[0])
	}
}
