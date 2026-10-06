package email

import (
	"net/url"
	"strings"
	"testing"
)

func TestTokenEmailLinks(t *testing.T) {
	for _, action := range []string{"verify your email", "reset your password"} {
		for _, target := range []string{
			"https://staging.example.com/auth/verify",
			"http://localhost:5173/auth/reset?returnTo=%2Fdashboard&token=old",
		} {
			t.Run(action+" "+target, func(t *testing.T) {
				const token = "token+with/slash?and&query=value#fragment"
				body, err := tokenEmailBody("alice", token, action, target)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(body, "Use the following token to "+action+": "+token+"\n") {
					t.Fatal("email must retain the original token")
				}
				lines := strings.Split(strings.TrimSpace(body), "\n")
				link, err := url.Parse(lines[len(lines)-1])
				if err != nil {
					t.Fatal(err)
				}
				original, err := url.Parse(target)
				if err != nil {
					t.Fatal(err)
				}
				if link.Scheme != original.Scheme || link.Host != original.Host || link.Path != original.Path {
					t.Fatal("link must use the configured application URL")
				}
				if link.Query().Get("token") != token || len(link.Query()["token"]) != 1 || link.Fragment != "" {
					t.Fatal("link must encode the complete token as a single query value")
				}
				if link.Query().Get("returnTo") != original.Query().Get("returnTo") {
					t.Fatal("link must preserve existing query parameters")
				}
			})
		}
	}
}

func TestTokenEmailWithoutLink(t *testing.T) {
	body, err := tokenEmailBody("alice", "token", "verify your email", "")
	if err != nil {
		t.Fatal(err)
	}
	if body != "Hello alice,\n\nUse the following token to verify your email: token\n" {
		t.Fatal("unset URLs must preserve the existing token-only email")
	}
}

func TestTokenEmailPreservesSemicolonQueryParameters(t *testing.T) {
	body, err := tokenEmailBody("alice", "new-token", "verify your email",
		"https://example.com/auth/verify?returnTo=/dashboard;mode=compact&other=value;part&token=old")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	link, err := url.Parse(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	query, err := url.ParseQuery(link.RawQuery)
	if err != nil {
		t.Fatal("email link query must have valid URL encoding")
	}
	if query.Get("returnTo") != "/dashboard;mode=compact" || query.Get("other") != "value;part" {
		t.Fatal("email links must preserve semicolons in existing query values")
	}
	if query.Get("token") != "new-token" || len(query["token"]) != 1 {
		t.Fatal("email link must replace the existing token")
	}
}

func TestTokenEmailRejectsInvalidLinksWithoutLeakingSecrets(t *testing.T) {
	for _, target := range []string{
		"/auth/verify", "javascript:secret", "https://", "https://secret@example.com/auth/reset",
		"https://example.com/auth/reset#secret", "https://example.com/%secret",
		"https://example.com/auth/reset?secret=%", "https://example.com/auth/reset?returnTo=/dashboard&token=%zzsecret",
	} {
		body, err := tokenEmailBody("alice", "secret-token", "reset your password", target)
		if err == nil || body != "" {
			t.Fatalf("expected invalid link to fail without returning an email body")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("link errors must not include URL credentials or tokens")
		}
	}
}
