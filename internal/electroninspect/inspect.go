package electroninspect

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/Code-Hex/browsercookie/internal/errdefs"
	"github.com/Code-Hex/browsercookie/internal/pathutil"
	"github.com/Code-Hex/browsercookie/internal/sqlitecopy"
)

const (
	maxScannedAssetSize = 16 << 20
)

type discoveredBundle struct {
	Bundle
	appPath       string
	resourcesPath string
	appAsarPath   string
	appDirPath    string
	unpackedPath  string
}

type packageManifest struct {
	Name        string `json:"name"`
	ProductName string `json:"productName"`
}

type storageCandidate struct {
	kind    string
	pattern string
}

// ResolveConfig derives session-root and keyring candidates from bundle metadata.
func ResolveConfig(app string, cfg Config) Config {
	app = strings.TrimSpace(app)
	cfg = normalizeConfig(cfg)
	bundles := discoverBundles(app, cfg.AppPaths)
	for i := range bundles {
		scanBundle(&bundles[i])
	}
	return resolveConfigFromBundles(app, cfg, bundles)
}

// Inspect reports persisted auth-related storage used by one Electron app.
func Inspect(app string, cfg Config) (*Report, error) {
	report := &Report{App: strings.TrimSpace(app)}
	cfg = normalizeConfig(cfg)
	bundles := discoverBundles(report.App, cfg.AppPaths)

	for i := range bundles {
		locations, signals := scanBundle(&bundles[i])
		report.Locations = append(report.Locations, locations...)
		report.Signals = append(report.Signals, signals...)
	}

	resolved := resolveConfigFromBundles(report.App, cfg, bundles)
	spec := browsercfg.ElectronSpec(report.App, resolved.SessionRoots, resolved.KeyringNames)

	report.Locations = append(report.Locations, probeFilesystem(resolved.SessionRoots)...)
	report.Locations = append(report.Locations, probeSecretLocations(spec, resolved.SessionRoots)...)

	report.Bundles = make([]Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		report.Bundles = append(report.Bundles, bundle.Bundle)
		if report.ElectronVersion == "" && bundle.ElectronVersion != "" {
			report.ElectronVersion = bundle.ElectronVersion
		}
	}
	if report.ElectronVersion != "" {
		report.ChromiumVersion = chromiumVersionForElectron(report.ElectronVersion)
	}

	report.Bundles = uniqueBundles(report.Bundles)
	report.Locations = uniqueLocations(report.Locations)
	report.Signals = uniqueSignals(report.Signals)
	sortBundles(report.Bundles)
	sortLocations(report.Locations)
	sortSignals(report.Signals)

	if len(report.Bundles) == 0 && len(report.Locations) == 0 && len(report.Signals) == 0 {
		return nil, errdefs.ErrNotFound
	}
	return report, nil
}

func normalizeConfig(cfg Config) Config {
	return Config{
		AppPaths:     uniqueNonEmptyStrings(cfg.AppPaths),
		SessionRoots: uniqueNonEmptyStrings(cfg.SessionRoots),
		KeyringNames: uniqueNonEmptyStrings(cfg.KeyringNames),
	}
}

func resolveConfigFromBundles(app string, cfg Config, bundles []discoveredBundle) Config {
	rootNames := candidateAppNames(app, bundles)
	cfg.SessionRoots = candidateSessionRoots(runtime.GOOS, rootNames, cfg.SessionRoots)
	cfg.KeyringNames = candidateKeyringNames(app, bundles, cfg.KeyringNames)
	return cfg
}

func candidateAppNames(app string, bundles []discoveredBundle) []string {
	values := []string{app}
	for _, bundle := range bundles {
		values = append(values,
			bundle.Name,
			bundle.DisplayName,
			bundle.PackageName,
			bundle.ProductName,
			strings.TrimSuffix(filepath.Base(bundle.Path), filepath.Ext(bundle.Path)),
		)
	}

	seen := map[string]struct{}{}
	names := make([]string, 0, len(values)*2)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		for _, candidate := range []string{value, strings.ToLower(value)} {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			names = append(names, candidate)
		}
	}
	return names
}

func candidateSessionRoots(goos string, names, overrides []string) []string {
	if len(overrides) > 0 {
		return uniqueNonEmptyStrings(overrides)
	}

	roots := make([]string, 0, len(names)*2)
	for _, name := range uniqueNonEmptyStrings(names) {
		switch goos {
		case "darwin":
			roots = append(roots, "~/Library/Application Support/"+name)
		case "linux":
			roots = append(roots, "$XDG_CONFIG_HOME/"+name, "~/.config/"+name)
		case "windows":
			roots = append(roots, "%APPDATA%/"+name, "%LOCALAPPDATA%/"+name)
		}
	}
	return uniqueNonEmptyStrings(roots)
}

func candidateKeyringNames(app string, bundles []discoveredBundle, overrides []string) []string {
	values := append([]string(nil), overrides...)
	values = append(values, app)
	for _, bundle := range bundles {
		values = append(values, bundle.Name, bundle.DisplayName, bundle.PackageName, bundle.ProductName)
	}
	return uniqueNonEmptyStrings(values)
}

func scanBundle(bundle *discoveredBundle) ([]Location, []Signal) {
	if bundle == nil {
		return nil, nil
	}

	var locations []Location
	var signals []Signal
	packageNamePriority := -1
	productNamePriority := -1

	scanAsset := func(assetPath string, data []byte) {
		if manifest, ok := parsePackageManifest(data); ok {
			priority := packageManifestPriority(bundle, assetPath)
			if manifest.Name != "" && priority > packageNamePriority {
				bundle.PackageName = manifest.Name
				packageNamePriority = priority
			}
			if manifest.ProductName != "" && priority > productNamePriority {
				bundle.ProductName = manifest.ProductName
				productNamePriority = priority
			}
		}

		assetLocations, assetSignals := scanAssetContent(assetPath, data)
		locations = append(locations, assetLocations...)
		signals = append(signals, assetSignals...)
	}

	if bundle.appAsarPath != "" {
		archive, err := openASAR(bundle.appAsarPath)
		if err == nil {
			defer func() { _ = archive.Close() }()
			for _, entry := range archive.entries {
				if !interestingBundleFile(entry.Path) || entry.Size > maxScannedAssetSize {
					continue
				}
				data, err := archive.ReadFile(entry)
				if err != nil {
					continue
				}
				scanAsset(bundle.appAsarPath+":"+entry.Path, data)
			}
		}
	}

	for _, root := range []string{bundle.appDirPath, bundle.unpackedPath, bundle.resourcesPath} {
		scanAssetDirectory(root, scanAsset)
	}
	return locations, signals
}

func scanAssetDirectory(root string, scanAsset func(string, []byte)) {
	root = strings.TrimSpace(root)
	if root == "" {
		return
	}
	info, err := os.Stat(root)
	if err != nil {
		return
	}
	if !info.IsDir() {
		return
	}

	_ = filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		if !interestingBundleFile(current) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxScannedAssetSize {
			return nil
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return nil
		}
		scanAsset(current, data)
		return nil
	})
}

func interestingBundleFile(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if base == "package.json" {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".cjs", ".mjs", ".json", ".node":
		return true
	default:
		return false
	}
}

func scanAssetContent(assetPath string, data []byte) ([]Location, []Signal) {
	var locations []Location
	var signals []Signal

	signalMatchers := []struct {
		kind    string
		details []string
	}{
		{kind: "uses_safe_storage", details: []string{"safeStorage"}},
		{kind: "uses_keytar", details: []string{"keytar"}},
		{kind: "uses_session_from_partition", details: []string{"session.fromPartition"}},
		{kind: "uses_session_from_path", details: []string{"session.fromPath"}},
		{
			kind: "overrides_user_data_path",
			details: []string{
				`app.setPath("userData"`,
				"app.setPath('userData'",
			},
		},
		{
			kind: "overrides_session_data_path",
			details: []string{
				`app.setPath("sessionData"`,
				"app.setPath('sessionData'",
			},
		},
	}
	locationMatchers := []struct {
		kind    string
		details []string
	}{
		{kind: "cookies", details: []string{"Cookies"}},
		{kind: "login_data", details: []string{"Login Data"}},
		{kind: "local_storage", details: []string{"Local Storage"}},
		{kind: "session_storage", details: []string{"Session Storage"}},
		{kind: "indexeddb", details: []string{"IndexedDB"}},
		{kind: "safe_storage", details: []string{"safeStorage"}},
		{kind: "keytar", details: []string{"keytar"}},
	}

	for _, matcher := range signalMatchers {
		for _, detail := range matcher.details {
			if !bytes.Contains(data, []byte(detail)) {
				continue
			}
			signals = append(signals, Signal{
				Kind:   matcher.kind,
				Detail: detail,
				Path:   assetPath,
			})
		}
	}
	for _, matcher := range locationMatchers {
		for _, detail := range matcher.details {
			if !bytes.Contains(data, []byte(detail)) {
				continue
			}
			if !shouldRecordReferencedLocation(assetPath, matcher.kind) {
				continue
			}
			locations = append(locations, Location{
				Kind:     matcher.kind,
				Status:   "referenced",
				Scope:    "app",
				Path:     assetPath,
				Evidence: []string{"matched string: " + detail},
			})
		}
	}
	return locations, signals
}

func shouldRecordReferencedLocation(assetPath, kind string) bool {
	switch kind {
	case "cookies", "login_data", "local_storage", "session_storage", "indexeddb":
		lower := strings.ToLower(filepath.ToSlash(assetPath))
		if strings.Contains(lower, ":node_modules/") || strings.Contains(lower, "/node_modules/") {
			return false
		}
		if strings.HasSuffix(lower, ".node") {
			return false
		}
	}
	return true
}

func packageManifestPriority(bundle *discoveredBundle, assetPath string) int {
	assetPath = filepath.ToSlash(assetPath)
	for _, candidate := range topLevelBundleManifestPaths(bundle) {
		if assetPath == candidate {
			return 2
		}
	}
	if strings.Contains(assetPath, ":node_modules/") || strings.Contains(assetPath, "/node_modules/") {
		return 0
	}
	if strings.HasSuffix(assetPath, ":package.json") || strings.HasSuffix(assetPath, "/package.json") || assetPath == "package.json" {
		return 1
	}
	return -1
}

func topLevelBundleManifestPaths(bundle *discoveredBundle) []string {
	if bundle == nil {
		return nil
	}

	var paths []string
	if bundle.appAsarPath != "" {
		paths = append(paths, filepath.ToSlash(bundle.appAsarPath)+":package.json")
	}
	for _, root := range []string{bundle.appDirPath, bundle.resourcesPath} {
		if root == "" {
			continue
		}
		paths = append(paths, filepath.ToSlash(filepath.Join(root, "package.json")))
	}
	return paths
}

func parsePackageManifest(data []byte) (packageManifest, bool) {
	var manifest packageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return packageManifest{}, false
	}
	if strings.TrimSpace(manifest.Name) == "" && strings.TrimSpace(manifest.ProductName) == "" {
		return packageManifest{}, false
	}
	return manifest, true
}

func probeFilesystem(sessionRoots []string) []Location {
	candidates := storageCandidates(sessionRoots)
	locations := make([]Location, 0, len(candidates))
	for _, candidate := range candidates {
		for _, concretePath := range pathutil.Expand([]string{candidate.pattern}) {
			root := candidateRootForPattern(candidate.pattern)
			scope := scopeForPath(root, concretePath)
			switch candidate.kind {
			case "cookies":
				location, ok := probeSQLiteLocation(
					candidate.kind,
					concretePath,
					scope,
					"cookies",
				)
				if ok {
					locations = append(locations, location)
				}
			case "login_data":
				location, ok := probeSQLiteLocation(
					candidate.kind,
					concretePath,
					scope,
					"logins",
				)
				if ok {
					locations = append(locations, location)
				}
			default:
				location, ok := probeStorageLocation(candidate.kind, concretePath, scope)
				if ok {
					locations = append(locations, location)
				}
			}
		}
	}
	return locations
}

func storageCandidates(sessionRoots []string) []storageCandidate {
	suffixes := []storageCandidate{
		{kind: "cookies", pattern: "Cookies"},
		{kind: "cookies", pattern: "Network/Cookies"},
		{kind: "login_data", pattern: "Login Data"},
		{kind: "local_storage", pattern: "Local Storage"},
		{kind: "session_storage", pattern: "Session Storage"},
		{kind: "indexeddb", pattern: "IndexedDB"},
		{kind: "indexeddb", pattern: "WebStorage/*/IndexedDB"},
		{kind: "cookies", pattern: "Partitions/*/Cookies"},
		{kind: "cookies", pattern: "Partitions/*/Network/Cookies"},
		{kind: "login_data", pattern: "Partitions/*/Login Data"},
		{kind: "local_storage", pattern: "Partitions/*/Local Storage"},
		{kind: "session_storage", pattern: "Partitions/*/Session Storage"},
		{kind: "indexeddb", pattern: "Partitions/*/IndexedDB"},
	}

	seen := map[string]struct{}{}
	out := make([]storageCandidate, 0, len(sessionRoots)*len(suffixes))
	for _, root := range uniqueNonEmptyStrings(sessionRoots) {
		root = strings.TrimRight(filepath.ToSlash(root), "/")
		for _, suffix := range suffixes {
			pattern := root + "/" + suffix.pattern
			key := suffix.kind + "\x00" + pattern
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, storageCandidate{
				kind:    suffix.kind,
				pattern: pattern,
			})
		}
	}
	return out
}

func candidateRootForPattern(pattern string) string {
	pattern = filepath.ToSlash(pattern)
	for _, marker := range []string{"/Partitions/*/", "/WebStorage/*/"} {
		if idx := strings.Index(pattern, marker); idx >= 0 {
			return pattern[:idx]
		}
	}
	switch {
	case strings.HasSuffix(pattern, "/Network/Cookies"):
		return strings.TrimSuffix(pattern, "/Network/Cookies")
	case strings.HasSuffix(pattern, "/Cookies"):
		return strings.TrimSuffix(pattern, "/Cookies")
	case strings.HasSuffix(pattern, "/Login Data"):
		return strings.TrimSuffix(pattern, "/Login Data")
	case strings.HasSuffix(pattern, "/Local Storage"):
		return strings.TrimSuffix(pattern, "/Local Storage")
	case strings.HasSuffix(pattern, "/Session Storage"):
		return strings.TrimSuffix(pattern, "/Session Storage")
	case strings.HasSuffix(pattern, "/IndexedDB"):
		return strings.TrimSuffix(pattern, "/IndexedDB")
	default:
		return pattern
	}
}

func scopeForPath(rootPattern, concretePath string) string {
	root := filepath.Clean(filepath.FromSlash(pathutil.ExpandPath(rootPattern)))
	current := filepath.Clean(concretePath)
	rel, err := filepath.Rel(root, current)
	if err != nil {
		return "default"
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) >= 2 && parts[0] == "Partitions" {
		return "partition:" + parts[1]
	}
	return "default"
}

func probeSQLiteLocation(kind, path, scope, requiredTable string) (Location, bool) {
	db, cleanup, err := sqlitecopy.Open(path)
	if err != nil {
		return Location{}, false
	}
	defer func() { _ = cleanup() }()

	ok, err := sqliteTableExists(db, requiredTable)
	if err != nil || !ok {
		return Location{}, false
	}

	evidence := []string{"sqlite table: " + requiredTable}
	if version, ok := sqliteMetaVersion(db); ok {
		evidence = append(evidence, fmt.Sprintf("meta.version: %d", version))
	}
	return Location{
		Kind:     kind,
		Status:   "present",
		Scope:    scope,
		Path:     path,
		Format:   "sqlite",
		Evidence: evidence,
	}, true
}

func sqliteTableExists(db *sql.DB, table string) (bool, error) {
	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
		table,
	).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return name == table, nil
}

func sqliteMetaVersion(db *sql.DB) (int, bool) {
	var raw string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'version'`).Scan(&raw); err != nil {
		return 0, false
	}
	var version int
	if _, err := fmt.Sscanf(raw, "%d", &version); err != nil {
		return 0, false
	}
	return version, true
}

func probeStorageLocation(kind, path, scope string) (Location, bool) {
	format, evidence, ok := storageFormat(kind, path)
	if !ok {
		return Location{}, false
	}
	return Location{
		Kind:     kind,
		Status:   "present",
		Scope:    scope,
		Path:     path,
		Format:   format,
		Evidence: evidence,
	}, true
}

func storageFormat(kind, path string) (string, []string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return "", nil, false
	}

	switch kind {
	case "local_storage":
		if leveldbPath, ok := findLevelDB(path, "leveldb"); ok {
			return "leveldb", []string{"leveldb: " + leveldbPath}, true
		}
		if hasLocalStorageFiles(path) {
			return "chromium_storage", []string{"localstorage files present"}, true
		}
	case "session_storage":
		if leveldbPath, ok := findLevelDB(path); ok {
			return "leveldb", []string{"leveldb: " + leveldbPath}, true
		}
		if hasExtension(path, ".sessionstorage") {
			return "chromium_storage", []string{"sessionstorage files present"}, true
		}
	case "indexeddb":
		if leveldbPath, ok := findLevelDB(path, "indexeddb.leveldb"); ok {
			return "leveldb", []string{"leveldb: " + leveldbPath}, true
		}
		if nested, ok := findNestedIndexedDB(path); ok {
			return "leveldb", []string{"leveldb: " + nested}, true
		}
	}
	return "", nil, false
}

func findLevelDB(root string, childNames ...string) (string, bool) {
	paths := []string{root}
	for _, child := range childNames {
		if child == "" {
			continue
		}
		paths = append(paths, filepath.Join(root, child))
	}
	for _, candidate := range paths {
		if hasLevelDBMarkers(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func hasLevelDBMarkers(root string) bool {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == "CURRENT", name == "LOCK", name == "LOG", name == "LOG.old":
			return true
		case strings.HasPrefix(name, "MANIFEST-"):
			return true
		case strings.HasSuffix(name, ".ldb"), strings.HasSuffix(name, ".log"):
			return true
		}
	}
	return false
}

func hasLocalStorageFiles(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".localstorage") || strings.HasSuffix(name, ".localstorage-journal") {
			return true
		}
	}
	return false
}

func hasExtension(root, ext string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ext) {
			return true
		}
	}
	return false
}

func findNestedIndexedDB(root string) (string, bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "indexeddb.leveldb" || strings.HasSuffix(name, ".indexeddb.leveldb") {
			candidate := filepath.Join(root, name)
			if hasLevelDBMarkers(candidate) {
				return candidate, true
			}
		}
	}
	return "", false
}

func uniqueBundles(bundles []Bundle) []Bundle {
	seen := map[string]struct{}{}
	out := make([]Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		key := canonicalPathKey(bundle.Path) + "\x00" + bundle.BundleID + "\x00" + bundle.Name + "\x00" + bundle.PackageName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, bundle)
	}
	return out
}

func uniqueLocations(locations []Location) []Location {
	seen := map[string]struct{}{}
	out := make([]Location, 0, len(locations))
	for _, location := range locations {
		key := location.Kind + "\x00" + location.Status + "\x00" + location.Scope + "\x00" + canonicalPathKey(location.Path) + "\x00" + location.Format + "\x00" + secretRefKey(location.SecretRef)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		location.Evidence = uniqueNonEmptyStrings(location.Evidence)
		out = append(out, location)
	}
	return out
}

func uniqueSignals(signals []Signal) []Signal {
	seen := map[string]struct{}{}
	out := make([]Signal, 0, len(signals))
	for _, signal := range signals {
		key := signal.Kind + "\x00" + signal.Detail + "\x00" + signal.Path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, signal)
	}
	return out
}

func secretRefKey(ref *SecretRef) string {
	if ref == nil {
		return ""
	}
	return strings.Join([]string{
		ref.Service,
		ref.Account,
		ref.Schema,
		ref.Name,
		ref.Folder,
		ref.Key,
		ref.Source,
	}, "\x00")
}

func sortBundles(bundles []Bundle) {
	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].Path < bundles[j].Path
	})
}

func sortLocations(locations []Location) {
	sort.Slice(locations, func(i, j int) bool {
		left := locations[i]
		right := locations[j]
		switch {
		case left.Kind != right.Kind:
			return left.Kind < right.Kind
		case left.Scope != right.Scope:
			return left.Scope < right.Scope
		default:
			return left.Path < right.Path
		}
	})
}

func sortSignals(signals []Signal) {
	sort.Slice(signals, func(i, j int) bool {
		left := signals[i]
		right := signals[j]
		switch {
		case left.Kind != right.Kind:
			return left.Kind < right.Kind
		case left.Detail != right.Detail:
			return left.Detail < right.Detail
		default:
			return left.Path < right.Path
		}
	})
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func chromiumVersionForElectron(version string) string {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 {
		return ""
	}
	key := parts[0] + "." + parts[1]
	if value, ok := electronToChromium[key]; ok {
		return value
	}
	if len(parts) >= 1 {
		key = parts[0] + ".0"
		return electronToChromium[key]
	}
	return ""
}

func canonicalPathKey(path string) string {
	path = filepath.Clean(path)
	switch runtime.GOOS {
	case "darwin", "windows":
		return strings.ToLower(path)
	default:
		return path
	}
}
