//go:build darwin

package browsercookie

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/Code-Hex/browsercookie/internal/secrets"
)

const (
	realBrowserEnv                = "BROWSERCOOKIE_REAL_BROWSER"
	mockChromeSafeStoragePassword = "mock_password"
)

func TestChromeReadsCookieFromRealBrowser(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv(realBrowserEnv) != "1" {
		t.Skip("opt-in real browser test")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("real browser test depends on GitHub Actions macOS runners")
	}
	chromeBinary, err := resolveChromeBinary()
	if err != nil {
		t.Skipf("Chrome binary is not available: %v", err)
	}
	restoreChromiumSecretProvider := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return mockSecretProvider{}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restoreChromiumSecretProvider
	})

	cookieName := fmt.Sprintf("browsercookie-%d", time.Now().UnixNano())
	cookieValue := "from-real-chrome"
	expiresAt := time.Now().Add(2 * time.Hour).UTC()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    cookieValue,
			Path:     "/",
			HttpOnly: true,
			Expires:  expiresAt,
		})
		_, _ = w.Write([]byte("<!doctype html><title>browsercookie</title>ok"))
	}))
	defer server.Close()

	profileDir := t.TempDir()
	session := startChromeDriverSession(t, chromeBinary, profileDir)
	if err := session.Navigate(server.URL); err != nil {
		t.Fatalf("navigate error = %v\nchromedriver output:\n%s", err, session.Output())
	}
	if _, ok := waitForWebDriverCookie(t, session, cookieName, cookieValue); !ok {
		t.Fatalf("webdriver cookie %q not found\nchromedriver output:\n%s", cookieName, session.Output())
	}
	session.Close(t)

	cookieFiles := waitForCookieFiles(t, profileDir)
	cookie := waitForCookieValue(t, cookieFiles, cookieName, cookieValue, session.Output)
	if cookie == nil {
		t.Fatalf("cookie %q not found in %v\nchromedriver output:\n%s", cookieName, cookieFiles, session.Output())
	}
}

type mockSecretProvider struct{}

func (mockSecretProvider) GenericPassword(service, account string) ([]byte, error) {
	if service != "Chrome Safe Storage" || account != "Chrome" {
		return nil, fmt.Errorf("unexpected secret lookup %q/%q", service, account)
	}
	return []byte(mockChromeSafeStoragePassword), nil
}

func resolveChromeBinary() (string, error) {
	if path := os.Getenv("BROWSERCOOKIE_CHROME_BIN"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	for _, candidate := range []string{
		"/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

func resolveChromeDriverBinary() (string, error) {
	if path := os.Getenv("BROWSERCOOKIE_CHROMEDRIVER_BIN"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	if root := os.Getenv("CHROMEWEBDRIVER"); root != "" {
		candidate := filepath.Join(root, "chromedriver")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	for _, candidate := range []string{
		"/usr/local/share/chromedriver-mac-arm64/chromedriver",
		"/opt/homebrew/bin/chromedriver",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

type chromeDriverSession struct {
	cancel    context.CancelFunc
	client    *http.Client
	cmd       *exec.Cmd
	outputBuf bytes.Buffer
	baseURL   string
	sessionID string
}

func startChromeDriverSession(t *testing.T, chromeBinary, profileDir string) *chromeDriverSession {
	t.Helper()

	driverBinary, err := resolveChromeDriverBinary()
	if err != nil {
		t.Skipf("ChromeDriver is not available: %v", err)
	}
	port, err := reserveLocalPort()
	if err != nil {
		t.Fatalf("reserveLocalPort() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, driverBinary, "--port="+strconv.Itoa(port), "--verbose")
	session := &chromeDriverSession{
		cancel:  cancel,
		client:  &http.Client{Timeout: 5 * time.Second},
		cmd:     cmd,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	}
	cmd.Stdout = &session.outputBuf
	cmd.Stderr = &session.outputBuf
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start chromedriver error = %v", err)
	}
	t.Cleanup(func() {
		session.Close(t)
	})

	if err := session.waitUntilReady(); err != nil {
		t.Fatalf("chromedriver failed to start: %v\n%s", err, session.Output())
	}
	if err := session.createSession(chromeBinary, profileDir); err != nil {
		t.Fatalf("createSession() error = %v\n%s", err, session.Output())
	}
	return session
}

func (s *chromeDriverSession) waitUntilReady() error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, s.baseURL+"/status", nil)
		if err != nil {
			return err
		}
		resp, err := s.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("timed out waiting for chromedriver status")
}

func (s *chromeDriverSession) createSession(chromeBinary, profileDir string) error {
	payload := map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{
				"browserName": "chrome",
				"goog:chromeOptions": map[string]any{
					"binary": chromeBinary,
					"args": []string{
						"--headless",
						"--disable-gpu",
						"--disable-background-networking",
						"--disable-component-update",
						"--disable-component-extensions-with-background-pages",
						"--disable-default-apps",
						"--disable-extensions",
						"--disable-sync",
						"--metrics-recording-only",
						"--mute-audio",
						"--no-first-run",
						"--no-default-browser-check",
						"--password-store=basic",
						"--user-data-dir=" + profileDir,
					},
				},
			},
		},
	}
	var response struct {
		SessionID string `json:"sessionId"`
		Value     struct {
			SessionID string `json:"sessionId"`
		} `json:"value"`
	}
	if err := s.doJSON(http.MethodPost, s.baseURL+"/session", payload, &response); err != nil {
		return err
	}
	s.sessionID = response.Value.SessionID
	if s.sessionID == "" {
		s.sessionID = response.SessionID
	}
	if s.sessionID == "" {
		return errors.New("chromedriver returned empty session id")
	}
	return nil
}

func (s *chromeDriverSession) Navigate(url string) error {
	return s.doJSON(http.MethodPost, s.baseURL+"/session/"+s.sessionID+"/url", map[string]string{"url": url}, nil)
}

func (s *chromeDriverSession) Cookies() ([]webdriverCookie, error) {
	var response struct {
		Value []webdriverCookie `json:"value"`
	}
	if err := s.doJSON(http.MethodGet, s.baseURL+"/session/"+s.sessionID+"/cookie", nil, &response); err != nil {
		return nil, err
	}
	return response.Value, nil
}

func (s *chromeDriverSession) Close(t *testing.T) {
	t.Helper()

	if s.cmd == nil || s.cmd.ProcessState != nil {
		return
	}
	if s.sessionID != "" {
		_ = s.doJSON(http.MethodDelete, s.baseURL+"/session/"+s.sessionID, nil, nil)
		s.sessionID = ""
	}
	s.cancel()
	if err := s.cmd.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("chromedriver wait error = %v\n%s", err, s.Output())
		}
	}
}

func (s *chromeDriverSession) Output() string {
	return s.outputBuf.String()
}

func (s *chromeDriverSession) doJSON(method, url string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webdriver %s %s returned %s: %s", method, url, resp.Status, bytes.TrimSpace(respBody))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}

func reserveLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("listener is not TCP")
	}
	return tcpAddr.Port, nil
}

func waitForCookieFiles(t *testing.T, profileDir string) []string {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		paths, err := findCookieFiles(profileDir)
		if err == nil && len(paths) > 0 {
			return paths
		}
		time.Sleep(250 * time.Millisecond)
	}

	_, err := findCookieFiles(profileDir)
	if err != nil {
		t.Fatalf("findCookieFiles() error = %v", err)
	}
	t.Fatalf("no Chromium cookie database found under %s", profileDir)
	return nil
}

func waitForCookieValue(
	t *testing.T,
	cookieFiles []string,
	cookieName string,
	cookieValue string,
	debugOutput func() string,
) *http.Cookie {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		cookies, err := Chrome(WithCookieFiles(cookieFiles...))
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		cookie := findCookieByName(cookies, cookieName)
		if cookie != nil && cookie.Value == cookieValue {
			return cookie
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("Chrome() never exposed cookie %q: %v\nchromedriver output:\n%s", cookieName, lastErr, debugOutput())
	}
	return nil
}

type webdriverCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

func waitForWebDriverCookie(
	t *testing.T,
	session *chromeDriverSession,
	cookieName string,
	cookieValue string,
) (*webdriverCookie, bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cookies, err := session.Cookies()
		if err == nil {
			for i := range cookies {
				if cookies[i].Name == cookieName && cookies[i].Value == cookieValue {
					return &cookies[i], true
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, false
}

func findCookieFiles(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) == "Cookies" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	return paths, nil
}

func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name == name {
			return cookie
		}
	}
	return nil
}
