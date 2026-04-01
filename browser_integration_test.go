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
	realBrowserEnv                  = "BROWSERCOOKIE_REAL_BROWSER"
	mockChromiumSafeStoragePassword = "mock_password"
)

func TestChromeReadsCookieFromRealBrowser(t *testing.T) {
	testChromiumReadsCookieFromRealBrowser(t, chromiumRealBrowserTestCase{
		name:          "chrome",
		webDriverName: "chrome",
		optionsKey:    "goog:chromeOptions",
		resolveBinary: resolveChromeBinary,
		resolveDriver: resolveChromeDriverBinary,
		load:          Chrome,
	})
}

func TestBraveReadsCookieFromRealBrowser(t *testing.T) {
	testChromiumReadsCookieFromCommandLineBrowser(t, chromiumCommandLineRealBrowserTestCase{
		name:          "brave",
		resolveBinary: resolveBraveBinary,
		load:          Brave,
	})
}

func TestEdgeReadsCookieFromRealBrowser(t *testing.T) {
	testChromiumReadsCookieFromRealBrowser(t, chromiumRealBrowserTestCase{
		name:          "edge",
		webDriverName: "MicrosoftEdge",
		optionsKey:    "ms:edgeOptions",
		resolveBinary: resolveEdgeBinary,
		resolveDriver: resolveEdgeDriverBinary,
		load:          Edge,
	})
}

func TestOperaReadsCookieFromRealBrowser(t *testing.T) {
	testChromiumReadsCookieFromCommandLineBrowser(t, chromiumCommandLineRealBrowserTestCase{
		name:          "opera",
		resolveBinary: resolveOperaBinary,
		load:          Opera,
	})
}

func TestVivaldiReadsCookieFromRealBrowser(t *testing.T) {
	testChromiumReadsCookieFromCommandLineBrowser(t, chromiumCommandLineRealBrowserTestCase{
		name:          "vivaldi",
		resolveBinary: resolveVivaldiBinary,
		load:          Vivaldi,
	})
}

func TestFirefoxReadsCookieFromRealBrowser(t *testing.T) {
	skipUnlessRealBrowserCI(t)

	firefoxBinary, err := resolveFirefoxBinary()
	if err != nil {
		t.Skipf("Firefox binary is not available: %v", err)
	}
	geckoDriverBinary, err := resolveGeckoDriverBinary()
	if err != nil {
		t.Skipf("geckodriver is not available: %v", err)
	}

	cookieName := fmt.Sprintf("browsercookie-%d", time.Now().UnixNano())
	cookieValue := "from-real-firefox"
	server := startCookieServer(t, cookieName, cookieValue)

	session := startWebDriverSession(t, geckoDriverBinary, firefoxSessionPayload(firefoxBinary), "geckodriver", webdriverProcessArgs("geckodriver")...)
	if err := session.Navigate(server.URL); err != nil {
		t.Fatalf("navigate error = %v\ngeckodriver output:\n%s", err, session.Output())
	}
	if _, ok := waitForWebDriverCookie(t, session, cookieName, cookieValue); !ok {
		t.Fatalf("webdriver cookie %q not found\ngeckodriver output:\n%s", cookieName, session.Output())
	}

	profileDir := session.StringCapability("moz:profile")
	if profileDir == "" {
		t.Fatalf("geckodriver did not return moz:profile\ngeckodriver output:\n%s", session.Output())
	}
	cookieFiles := waitForFilesByBaseName(t, profileDir, "cookies.sqlite")
	cookie := waitForCookieValue(t, Firefox, "Firefox", cookieFiles, cookieName, cookieValue, session.Output)
	if cookie == nil {
		t.Fatalf("cookie %q not found in %v\ngeckodriver output:\n%s", cookieName, cookieFiles, session.Output())
	}
	session.Close(t)
}

// Safari automation sessions use isolated browser state, so this only verifies
// that Safari itself received the cookie under WebDriver.
func TestSafariReadsCookieFromAutomationSession(t *testing.T) {
	skipUnlessRealBrowserCI(t)

	safariDriverBinary, err := resolveSafariDriverBinary()
	if err != nil {
		t.Skipf("safaridriver is not available: %v", err)
	}

	cookieName := fmt.Sprintf("browsercookie-%d", time.Now().UnixNano())
	cookieValue := "from-real-safari"
	server := startCookieServer(t, cookieName, cookieValue)

	session := startWebDriverSession(t, safariDriverBinary, safariSessionPayload(), "safaridriver", webdriverProcessArgs("safaridriver")...)
	if err := session.Navigate(server.URL); err != nil {
		t.Fatalf("navigate error = %v\nsafaridriver output:\n%s", err, session.Output())
	}
	if _, ok := waitForWebDriverCookie(t, session, cookieName, cookieValue); !ok {
		t.Fatalf("webdriver cookie %q not found\nsafaridriver output:\n%s", cookieName, session.Output())
	}
	session.Close(t)
}

type mockSecretProvider struct{}

func (mockSecretProvider) GenericPassword(service, account string) ([]byte, error) {
	switch service + "/" + account {
	case "Chrome Safe Storage/Chrome",
		"Chromium Safe Storage/Chromium",
		"Brave Safe Storage/Brave",
		"Opera Safe Storage/Opera",
		"Vivaldi Safe Storage/Vivaldi",
		"Microsoft Edge Safe Storage/Microsoft Edge",
		"Microsoft Edge Dev Safe Storage/Microsoft Edge Dev":
		return []byte(mockChromiumSafeStoragePassword), nil
	default:
		return nil, fmt.Errorf("unexpected secret lookup %q/%q", service, account)
	}
}

func resolveBraveBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_BRAVE_BIN", "", []string{
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	})
}

func resolveChromeBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_CHROME_BIN", "", []string{
		"/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	})
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
	return resolveBinary("", "chromedriver", []string{
		"/usr/local/share/chromedriver-mac-arm64/chromedriver",
		"/usr/local/bin/chromedriver",
		"/opt/homebrew/bin/chromedriver",
	})
}

func resolveEdgeBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_EDGE_BIN", "", []string{
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	})
}

func resolveEdgeDriverBinary() (string, error) {
	if root := os.Getenv("EDGEWEBDRIVER"); root != "" {
		candidate := filepath.Join(root, "msedgedriver")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return resolveBinary("BROWSERCOOKIE_MSEDGEDRIVER_BIN", "msedgedriver", []string{
		"/usr/local/bin/msedgedriver",
		"/opt/homebrew/bin/msedgedriver",
	})
}

func resolveFirefoxBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_FIREFOX_BIN", "", []string{
		"/Applications/Firefox.app/Contents/MacOS/firefox",
	})
}

func resolveOperaBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_OPERA_BIN", "", []string{
		"/Applications/Opera.app/Contents/MacOS/Opera",
	})
}

func resolveGeckoDriverBinary() (string, error) {
	if root := os.Getenv("GECKOWEBDRIVER"); root != "" {
		candidate := filepath.Join(root, "geckodriver")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return resolveBinary("BROWSERCOOKIE_GECKODRIVER_BIN", "geckodriver", []string{
		"/usr/local/bin/geckodriver",
		"/opt/homebrew/bin/geckodriver",
	})
}

func resolveSafariDriverBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_SAFARIDRIVER_BIN", "safaridriver", []string{
		"/System/Cryptexes/App/usr/bin/safaridriver",
		"/usr/bin/safaridriver",
	})
}

func resolveVivaldiBinary() (string, error) {
	return resolveBinary("BROWSERCOOKIE_VIVALDI_BIN", "", []string{
		"/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
	})
}

func resolveBinary(explicitEnv, executableName string, candidates []string) (string, error) {
	if explicitEnv != "" {
		if path := os.Getenv(explicitEnv); path != "" {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}
	if executableName != "" {
		if path, err := exec.LookPath(executableName); err == nil {
			return path, nil
		}
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

type chromiumRealBrowserTestCase struct {
	name          string
	webDriverName string
	optionsKey    string
	resolveBinary func() (string, error)
	resolveDriver func() (string, error)
	load          func(...Option) ([]*http.Cookie, error)
}

type chromiumCommandLineRealBrowserTestCase struct {
	name          string
	resolveBinary func() (string, error)
	load          func(...Option) ([]*http.Cookie, error)
}

func testChromiumReadsCookieFromRealBrowser(t *testing.T, tc chromiumRealBrowserTestCase) {
	t.Helper()

	skipUnlessRealBrowserCI(t)

	browserBinary, err := tc.resolveBinary()
	if err != nil {
		t.Skipf("%s binary is not available: %v", tc.name, err)
	}
	driverBinary, err := tc.resolveDriver()
	if err != nil {
		t.Skipf("%s driver is not available: %v", tc.name, err)
	}

	restoreChromiumSecretProvider := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return mockSecretProvider{}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restoreChromiumSecretProvider
	})

	cookieName := fmt.Sprintf("browsercookie-%d", time.Now().UnixNano())
	cookieValue := "from-real-" + tc.name
	server := startCookieServer(t, cookieName, cookieValue)

	profileDir := t.TempDir()
	session := startWebDriverSession(t, driverBinary, chromiumSessionPayload(tc.webDriverName, tc.optionsKey, browserBinary, profileDir), tc.name+"driver", webdriverProcessArgs(tc.name+"driver")...)
	if err := session.Navigate(server.URL); err != nil {
		t.Fatalf("navigate error = %v\n%s output:\n%s", err, tc.name+"driver", session.Output())
	}
	if _, ok := waitForWebDriverCookie(t, session, cookieName, cookieValue); !ok {
		t.Fatalf("webdriver cookie %q not found\n%s output:\n%s", cookieName, tc.name+"driver", session.Output())
	}
	session.Close(t)

	cookieFiles := waitForFilesByBaseName(t, profileDir, "Cookies")
	cookie := waitForCookieValue(t, tc.load, tc.name, cookieFiles, cookieName, cookieValue, session.Output)
	if cookie == nil {
		t.Fatalf("cookie %q not found in %v\n%s output:\n%s", cookieName, cookieFiles, tc.name+"driver", session.Output())
	}
}

func testChromiumReadsCookieFromCommandLineBrowser(t *testing.T, tc chromiumCommandLineRealBrowserTestCase) {
	t.Helper()

	skipUnlessRealBrowserCI(t)

	browserBinary, err := tc.resolveBinary()
	if err != nil {
		t.Skipf("%s binary is not available: %v", tc.name, err)
	}

	restoreChromiumSecretProvider := chromiumSecretProvider
	chromiumSecretProvider = func() secrets.Provider {
		return mockSecretProvider{}
	}
	t.Cleanup(func() {
		chromiumSecretProvider = restoreChromiumSecretProvider
	})

	cookieName := fmt.Sprintf("browsercookie-%d", time.Now().UnixNano())
	cookieValue := "from-real-" + tc.name
	server := startCookieServer(t, cookieName, cookieValue)

	profileDir := t.TempDir()
	browserOutput := runChromiumBrowserCommand(t, tc.name, browserBinary, profileDir, server.URL)

	cookieFiles := waitForFilesByBaseName(t, profileDir, "Cookies")
	cookie := waitForCookieValue(t, tc.load, tc.name, cookieFiles, cookieName, cookieValue, func() string {
		return browserOutput
	})
	if cookie == nil {
		t.Fatalf("cookie %q not found in %v\n%s output:\n%s", cookieName, cookieFiles, tc.name, browserOutput)
	}
}

func skipUnlessRealBrowserCI(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "darwin" || os.Getenv(realBrowserEnv) != "1" {
		t.Skip("opt-in real browser test")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("real browser test depends on GitHub Actions macOS runners")
	}
}

func startCookieServer(t *testing.T, cookieName, cookieValue string) *httptest.Server {
	t.Helper()

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
	t.Cleanup(server.Close)
	return server
}

func runChromiumBrowserCommand(t *testing.T, browserName, browserBinary, profileDir, url string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logFile, err := os.CreateTemp(t.TempDir(), browserName+"-*.log")
	if err != nil {
		t.Fatalf("create %s log file error = %v", browserName, err)
	}
	logPath := logFile.Name()

	cmd := exec.CommandContext(ctx, browserBinary, chromiumCommandLineArgs(profileDir, url)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	runErr := cmd.Run()
	_ = logFile.Close()

	output := readCommandOutput(logPath)
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		t.Fatalf("%s browser timed out\nbrowser output:\n%s", browserName, output)
	case runErr != nil:
		t.Fatalf("%s browser command failed: %v\nbrowser output:\n%s", browserName, runErr, output)
	}
	return output
}

func chromiumCommandLineArgs(profileDir, url string) []string {
	return []string{
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
		"--use-mock-keychain",
		"--dump-dom",
		"--user-data-dir=" + profileDir,
		url,
	}
}

func chromiumSessionPayload(browserName, optionsKey, browserBinary, profileDir string) map[string]any {
	return map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{
				"browserName": browserName,
				optionsKey: map[string]any{
					"binary": browserBinary,
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
						"--use-mock-keychain",
						"--user-data-dir=" + profileDir,
					},
				},
			},
		},
	}
}

func firefoxSessionPayload(firefoxBinary string) map[string]any {
	return map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{
				"browserName": "firefox",
				"moz:firefoxOptions": map[string]any{
					"binary": firefoxBinary,
					"args": []string{
						"-headless",
					},
				},
			},
		},
	}
}

func safariSessionPayload() map[string]any {
	return map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{
				"browserName": "Safari",
			},
		},
	}
}

type webDriverSession struct {
	cancel       context.CancelFunc
	client       *http.Client
	cmd          *exec.Cmd
	logFile      *os.File
	logPath      string
	baseURL      string
	sessionID    string
	driverName   string
	capabilities map[string]any
}

func startWebDriverSession(t *testing.T, driverBinary string, payload map[string]any, driverName string, processArgs ...string) *webDriverSession {
	t.Helper()

	port, err := reserveLocalPort()
	if err != nil {
		t.Fatalf("reserveLocalPort() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	args := append(webdriverPortArgs(driverName, port), processArgs...)
	cmd := exec.CommandContext(ctx, driverBinary, args...)
	logFile, err := os.CreateTemp(t.TempDir(), driverName+"-*.log")
	if err != nil {
		cancel()
		t.Fatalf("create %s log file error = %v", driverName, err)
	}
	session := &webDriverSession{
		cancel:     cancel,
		client:     &http.Client{Timeout: webdriverRequestTimeout(driverName)},
		cmd:        cmd,
		logFile:    logFile,
		logPath:    logFile.Name(),
		baseURL:    fmt.Sprintf("http://127.0.0.1:%d", port),
		driverName: driverName,
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		cancel()
		t.Fatalf("start %s error = %v", driverName, err)
	}
	t.Cleanup(func() {
		session.Close(t)
	})

	if err := session.waitUntilReady(); err != nil {
		t.Fatalf("%s failed to start: %v\n%s", driverName, err, session.Output())
	}
	if err := session.createSession(payload); err != nil {
		t.Fatalf("createSession() error = %v\n%s", err, session.Output())
	}
	return session
}

func webdriverPortArgs(driverName string, port int) []string {
	switch driverName {
	case "safaridriver":
		return []string{"-p", strconv.Itoa(port)}
	default:
		return []string{"--port=" + strconv.Itoa(port)}
	}
}

func webdriverProcessArgs(driverName string) []string {
	switch driverName {
	case "geckodriver", "safaridriver":
		return nil
	default:
		return []string{"--verbose"}
	}
}

func webdriverRequestTimeout(driverName string) time.Duration {
	switch driverName {
	case "geckodriver", "safaridriver":
		return 30 * time.Second
	default:
		return 5 * time.Second
	}
}

func (s *webDriverSession) waitUntilReady() error {
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
	return errors.New("timed out waiting for webdriver status")
}

func (s *webDriverSession) createSession(payload map[string]any) error {
	var response struct {
		SessionID string `json:"sessionId"`
		Value     struct {
			SessionID    string         `json:"sessionId"`
			Capabilities map[string]any `json:"capabilities"`
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
		return errors.New("webdriver returned empty session id")
	}
	s.capabilities = response.Value.Capabilities
	return nil
}

func (s *webDriverSession) Navigate(url string) error {
	return s.doJSON(http.MethodPost, s.baseURL+"/session/"+s.sessionID+"/url", map[string]string{"url": url}, nil)
}

func (s *webDriverSession) Cookies() ([]webdriverCookie, error) {
	var response struct {
		Value []webdriverCookie `json:"value"`
	}
	if err := s.doJSON(http.MethodGet, s.baseURL+"/session/"+s.sessionID+"/cookie", nil, &response); err != nil {
		return nil, err
	}
	return response.Value, nil
}

func (s *webDriverSession) Close(t *testing.T) {
	t.Helper()

	if s.cmd == nil || s.cmd.ProcessState != nil {
		return
	}
	if s.sessionID != "" {
		_ = s.doJSON(http.MethodDelete, s.baseURL+"/session/"+s.sessionID, nil, nil)
		s.sessionID = ""
	}
	s.cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("%s wait error = %v\n%s", s.driverName, err, s.Output())
			}
		}
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("%s kill error = %v\n%s", s.driverName, err, s.Output())
				}
			}
		case <-time.After(2 * time.Second):
			// Firefox likes to keep inherited descriptors alive via child processes.
			// At this point the driver has been killed, so don't let cleanup hang forever.
		}
	}
	if s.logFile != nil {
		_ = s.logFile.Close()
		s.logFile = nil
	}
}

func (s *webDriverSession) Output() string {
	return readCommandOutput(s.logPath)
}

func (s *webDriverSession) StringCapability(key string) string {
	if s.capabilities == nil {
		return ""
	}
	value, ok := s.capabilities[key]
	if !ok {
		return ""
	}
	asString, _ := value.(string)
	return asString
}

func (s *webDriverSession) doJSON(method, url string, payload any, out any) error {
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

func waitForFilesByBaseName(t *testing.T, root string, baseName string) []string {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		paths, err := findFilesByBaseName(root, baseName)
		if err == nil && len(paths) > 0 {
			return paths
		}
		time.Sleep(250 * time.Millisecond)
	}

	_, err := findFilesByBaseName(root, baseName)
	if err != nil {
		t.Fatalf("findFilesByBaseName() error = %v", err)
	}
	t.Fatalf("no %q file found under %s", baseName, root)
	return nil
}

func waitForCookieValue(
	t *testing.T,
	load func(...Option) ([]*http.Cookie, error),
	browserName string,
	cookieFiles []string,
	cookieName string,
	cookieValue string,
	debugOutput func() string,
) *http.Cookie {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		cookies, err := load(WithCookieFiles(cookieFiles...))
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
		t.Fatalf("%s() never exposed cookie %q: %v\ndebug output:\n%s", browserName, cookieName, lastErr, debugOutput())
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
	session *webDriverSession,
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

func findFilesByBaseName(root, baseName string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) == baseName {
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

func readCommandOutput(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name == name {
			return cookie
		}
	}
	return nil
}
