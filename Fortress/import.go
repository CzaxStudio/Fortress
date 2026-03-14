package main

// ─── import.go — Fortress Package Manager ────────────────────────────────────
//
//  The Fortress package system lets users publish, install, and import
//  community libraries written in .frt (Fortress DSL).
//
//  COMMANDS:
//    fortress get site=<name>              Install a library from the registry
//    fortress get site=<name>@<version>    Install specific version
//    fortress <file.frt> create lib site=<name>    Publish a .frt file as a library
//    fortress * create lib site=<name>             Publish ALL .frt files in CWD
//
//  USAGE IN SCRIPTS:
//    import mylib
//    import mylib as ml
//    mylib.myProbe("arg")
//
//  REGISTRY:
//    Libraries are stored locally in:
//      Windows : %APPDATA%\Fortress\libs\<name>\
//      Linux   : ~/.fortress/libs/<name>/
//      macOS   : ~/Library/Fortress/libs/<name>/
//
//    The registry index is a JSON file at <libsDir>/registry.json
//    Each entry contains name, version, description, author, license,
//    site (unique ID), homepage, install date, files.
//
//  LIBRARY FORMAT:
//    A library is a directory containing:
//      *.frt         — Fortress source files
//      fortress.pkg  — Package manifest (JSON)
//
//  PUBLISHING:
//    Currently libraries are stored locally only (offline-first).
//    A future release will add a central registry server.
//    For now, libraries can be shared as .frtpkg zip archives.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

// ─── Registry Types ───────────────────────────────────────────────────────────

// PackageManifest is stored as fortress.pkg inside each library directory.
type PackageManifest struct {
	Name        string   `json:"name"`
	Site        string   `json:"site"` // unique ID / slug
	Version     string   `json:"version"`
	Description string   `json:"description"`
	LongDesc    string   `json:"long_description"`
	Author      string   `json:"author"`
	License     string   `json:"license"`
	Usage       string   `json:"usage"`
	Tags        []string `json:"tags"`
	Homepage    string   `json:"homepage"`
	Repository  string   `json:"repository"`
	MinFortress string   `json:"min_fortress"`
	Files       []string `json:"files"`
	Exports     []string `json:"exports"` // probe names exported
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// RegistryEntry is stored in the global registry.json index.
type RegistryEntry struct {
	Name        string `json:"name"`
	Site        string `json:"site"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	License     string `json:"license"`
	InstalledAt string `json:"installed_at"`
	LibDir      string `json:"lib_dir"`
}

// Registry is the global local index of installed packages.
type Registry struct {
	Version  string                   `json:"registry_version"`
	Packages map[string]RegistryEntry `json:"packages"` // keyed by site name
}

// ─── Directory Helpers ────────────────────────────────────────────────────────

func libsDir() string {
	switch runtime.GOOS {
	case "windows":
		if app := os.Getenv("APPDATA"); app != "" {
			return filepath.Join(app, "Fortress", "libs")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Fortress", "libs")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Fortress", "libs")
	default: // linux + bsd
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "fortress", "libs")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".fortress", "libs")
	}
}

func registryPath() string {
	return filepath.Join(libsDir(), "registry.json")
}

func ensureLibsDir() error {
	return os.MkdirAll(libsDir(), 0755)
}

// ─── Registry I/O ─────────────────────────────────────────────────────────────

func loadRegistry() Registry {
	reg := Registry{
		Version:  "1",
		Packages: map[string]RegistryEntry{},
	}
	data, err := os.ReadFile(registryPath())
	if err != nil {
		return reg
	}
	_ = json.Unmarshal(data, &reg)
	if reg.Packages == nil {
		reg.Packages = map[string]RegistryEntry{}
	}
	return reg
}

func saveRegistry(reg Registry) error {
	if err := ensureLibsDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(registryPath(), data, 0644)
}

// ─── Name Validation ──────────────────────────────────────────────────────────

var validSiteName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_\-]{1,63}$`)

func validateSiteName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("library name cannot be empty")
	}
	if !validSiteName.MatchString(name) {
		return fmt.Errorf("library name must start with a letter, contain only letters/digits/dash/underscore, and be 2–64 chars")
	}
	reserved := []string{"fortress", "std", "stdlib", "core", "main", "builtin", "import", "get", "run", "create"}
	for _, r := range reserved {
		if strings.EqualFold(name, r) {
			return fmt.Errorf("'%s' is a reserved name", name)
		}
	}
	return nil
}

// ─── CMD: fortress get site=<name> ───────────────────────────────────────────

func cmdGet(args []string) {
	// Parse: site=<name> or site=<name>@<version>
	site := ""
	version := "latest"
	for _, a := range args {
		if strings.HasPrefix(a, "site=") {
			val := strings.TrimPrefix(a, "site=")
			if at := strings.Index(val, "@"); at >= 0 {
				site = val[:at]
				version = val[at+1:]
			} else {
				site = val
			}
		}
	}
	if site == "" {
		fmt.Println("  ✖ Usage: fortress get site=<library-name>")
		fmt.Println("         fortress get site=<library-name>@<version>")
		fmt.Println()
		fmt.Println("  Available installed libraries:")
		cmdList()
		return
	}
	site = strings.ToLower(strings.TrimSpace(site))
	if err := validateSiteName(site); err != nil {
		fmt.Printf("  ✖ Invalid library name: %v\n", err)
		return
	}

	reg := loadRegistry()
	if _, exists := reg.Packages[site]; exists {
		fmt.Printf("  ℹ  Library '%s' is already installed.\n", site)
		fmt.Printf("     Use 'fortress list' to see installed libraries.\n")
		fmt.Printf("     To reinstall, run 'fortress remove site=%s' first.\n", site)
		return
	}

	fmt.Printf("  ⬡  Fortress Package Manager\n")
	fmt.Printf("  ─────────────────────────────────────────────────\n")
	fmt.Printf("  [*] Looking up '%s'", site)
	if version != "latest" {
		fmt.Printf(" @ %s", version)
	}
	fmt.Println("...")

	// Try to fetch from registry sources
	pkg, pkgFiles, err := fetchPackage(site, version)
	if err != nil {
		fmt.Printf("  ✖ Could not install '%s': %v\n", site, err)
		fmt.Printf("\n  Hint: Libraries are shared as .frtpkg files.\n")
		fmt.Printf("  To install from a local file:\n")
		fmt.Printf("    fortress get file=path/to/library.frtpkg\n")
		return
	}

	// Install the package
	targetDir := filepath.Join(libsDir(), site)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Printf("  ✖ Could not create install directory: %v\n", err)
		return
	}

	// Write all files
	for fname, fdata := range pkgFiles {
		dest := filepath.Join(targetDir, fname)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			continue
		}
		if err := os.WriteFile(dest, fdata, 0644); err != nil {
			fmt.Printf("  ✖ Failed to write %s: %v\n", fname, err)
			return
		}
	}

	// Write manifest
	manData, _ := json.MarshalIndent(pkg, "", "  ")
	_ = os.WriteFile(filepath.Join(targetDir, "fortress.pkg"), manData, 0644)

	// Update registry
	reg.Packages[site] = RegistryEntry{
		Name:        pkg.Name,
		Site:        pkg.Site,
		Version:     pkg.Version,
		Description: pkg.Description,
		Author:      pkg.Author,
		License:     pkg.License,
		InstalledAt: time.Now().Format(time.RFC3339),
		LibDir:      targetDir,
	}
	if err := saveRegistry(reg); err != nil {
		fmt.Printf("  ⚠  Installed but failed to update registry: %v\n", err)
	}

	fmt.Printf("\n  ✔ Installed: %s v%s\n", pkg.Name, pkg.Version)
	fmt.Printf("  ✔ Location : %s\n", targetDir)
	fmt.Printf("  ✔ Author   : %s\n", pkg.Author)
	fmt.Printf("  ✔ License  : %s\n", pkg.License)
	fmt.Printf("\n  Usage in your script:\n")
	fmt.Printf("    import %s\n", site)
	if len(pkg.Exports) > 0 {
		fmt.Printf("    %s.%s(...)\n", site, pkg.Exports[0])
	}
	fmt.Println()
}

// cmdGetFile installs from a local .frtpkg file
func cmdGetFile(filePath string) {
	fmt.Printf("  [*] Installing from local package: %s\n", filePath)

	pkg, pkgFiles, err := readFrtpkg(filePath)
	if err != nil {
		fmt.Printf("  ✖ Failed to read package: %v\n", err)
		return
	}

	site := strings.ToLower(pkg.Site)
	if err := validateSiteName(site); err != nil {
		fmt.Printf("  ✖ Invalid package name: %v\n", err)
		return
	}

	reg := loadRegistry()
	if _, exists := reg.Packages[site]; exists {
		fmt.Printf("  ℹ  Library '%s' is already installed (v%s).\n", site, reg.Packages[site].Version)
		fmt.Printf("     Overwrite? [y/N]: ")
		var ans string
		fmt.Scanln(&ans)
		if strings.ToLower(strings.TrimSpace(ans)) != "y" {
			fmt.Println("  Aborted.")
			return
		}
	}

	targetDir := filepath.Join(libsDir(), site)
	os.MkdirAll(targetDir, 0755)

	for fname, fdata := range pkgFiles {
		dest := filepath.Join(targetDir, filepath.Clean(fname))
		os.MkdirAll(filepath.Dir(dest), 0755)
		os.WriteFile(dest, fdata, 0644)
	}

	manData, _ := json.MarshalIndent(pkg, "", "  ")
	os.WriteFile(filepath.Join(targetDir, "fortress.pkg"), manData, 0644)

	reg.Packages[site] = RegistryEntry{
		Name:        pkg.Name,
		Site:        pkg.Site,
		Version:     pkg.Version,
		Description: pkg.Description,
		Author:      pkg.Author,
		License:     pkg.License,
		InstalledAt: time.Now().Format(time.RFC3339),
		LibDir:      targetDir,
	}
	saveRegistry(reg)

	fmt.Printf("  ✔ Installed '%s' v%s from local file.\n", pkg.Name, pkg.Version)
}

// ─── CMD: fortress * create lib site=<name> ──────────────────────────────────

func cmdCreateLib(sourceArgs []string, extraArgs []string) {
	// Parse source pattern and site name
	site := ""
	for _, a := range extraArgs {
		if strings.HasPrefix(a, "site=") {
			site = strings.TrimPrefix(a, "site=")
		}
	}
	if site == "" {
		fmt.Println("  ✖ Usage: fortress <file.frt> create lib site=<library-name>")
		fmt.Println("           fortress * create lib site=<library-name>")
		return
	}
	site = strings.ToLower(strings.TrimSpace(site))
	if err := validateSiteName(site); err != nil {
		fmt.Printf("  ✖ %v\n", err)
		return
	}

	// Check for name conflict in local registry
	reg := loadRegistry()
	if existing, exists := reg.Packages[site]; exists {
		fmt.Printf("  ✖ A library named '%s' is already installed locally (v%s by %s).\n",
			site, existing.Version, existing.Author)
		fmt.Printf("     Please choose a different name. Suggestions:\n")
		fmt.Printf("       %s2  |  my-%s  |  %s-lib\n", site, site, site)
		return
	}

	// Collect source .frt files
	var frtFiles []string
	if len(sourceArgs) == 1 && sourceArgs[0] == "*" {
		entries, err := os.ReadDir(".")
		if err != nil {
			fmt.Printf("  ✖ Could not read current directory: %v\n", err)
			return
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".frt") {
				frtFiles = append(frtFiles, e.Name())
			}
		}
		if len(frtFiles) == 0 {
			fmt.Println("  ✖ No .frt files found in current directory.")
			return
		}
	} else {
		for _, s := range sourceArgs {
			if !strings.HasSuffix(s, ".frt") {
				s += ".frt"
			}
			if _, err := os.Stat(s); err != nil {
				fmt.Printf("  ✖ File not found: %s\n", s)
				return
			}
			frtFiles = append(frtFiles, s)
		}
	}

	// Scan files for exported probe names
	exports := scanExports(frtFiles)

	// Print header
	fmt.Printf("\n  ⬡  Fortress Library Creator\n")
	fmt.Printf("  ─────────────────────────────────────────────────\n")
	fmt.Printf("  Creating library: %s\n", site)
	fmt.Printf("  Source files   : %s\n", strings.Join(frtFiles, ", "))
	if len(exports) > 0 {
		fmt.Printf("  Detected probes: %s\n", strings.Join(exports, ", "))
	}
	fmt.Printf("\n  Please fill in the following information.\n")
	fmt.Printf("  All fields are required for publishing.\n")
	fmt.Printf("  ─────────────────────────────────────────────────\n\n")

	reader := bufio.NewReader(os.Stdin)

	// Prompt helper — loops until non-empty
	prompt := func(label, hint string, required bool) string {
		for {
			if hint != "" {
				fmt.Printf("  %s\n  (%s)\n  > ", label, hint)
			} else {
				fmt.Printf("  %s\n  > ", label)
			}
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" {
				return line
			}
			if !required {
				return ""
			}
			fmt.Printf("  ⚠  This field is required. Please enter a value.\n\n")
		}
	}

	// Choice prompt
	choice := func(label string, options []string) string {
		for {
			fmt.Printf("  %s\n", label)
			for i, o := range options {
				fmt.Printf("    [%d] %s\n", i+1, o)
			}
			fmt.Printf("  > ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			// Accept number or text
			for i, o := range options {
				if line == fmt.Sprintf("%d", i+1) || strings.EqualFold(line, o) {
					return o
				}
			}
			// Partial match
			for _, o := range options {
				if strings.Contains(strings.ToLower(o), strings.ToLower(line)) {
					return o
				}
			}
			fmt.Printf("  ⚠  Please choose a number from 1–%d.\n\n", len(options))
		}
	}

	// ── Collect metadata ──────────────────────────────────────────────────

	displayName := prompt(
		"Library display name (human-readable, e.g. 'Network Utils'):",
		"shown to users in package listings",
		true,
	)

	version := prompt(
		"Version (e.g. 1.0.0):",
		"use semantic versioning: major.minor.patch",
		true,
	)
	// Basic semver cleanup
	if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+$`, version); !matched {
		if matched2, _ := regexp.MatchString(`^\d+\.\d+$`, version); matched2 {
			version += ".0"
		} else if matched3, _ := regexp.MatchString(`^\d+$`, version); matched3 {
			version += ".0.0"
		}
	}

	author := prompt(
		"Author name (your name or organisation):",
		"",
		true,
	)

	description := prompt(
		"Short description (one line, max 120 chars):",
		"e.g. 'Collection of DNS utilities and zone analysis tools'",
		true,
	)
	if len(description) > 120 {
		description = description[:120]
		fmt.Printf("  (truncated to 120 chars)\n")
	}

	longDesc := prompt(
		"Long description (explain what the library does in detail):",
		"What does it do? Who is it for? What problems does it solve?",
		true,
	)

	usageExample := prompt(
		"Usage example (show how to import and call the library):",
		fmt.Sprintf("e.g.  import %s\\n  %s.myProbe(\"example.com\")", site, site),
		true,
	)

	license := choice(
		"License:",
		[]string{"MIT", "Apache-2.0", "GPL-3.0", "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "AGPL-3.0", "Proprietary", "Public Domain (Unlicense)"},
	)

	tagsRaw := prompt(
		"Tags / keywords (comma-separated, e.g. dns,recon,network):",
		"helps users find your library",
		true,
	)
	var tags []string
	for _, t := range strings.Split(tagsRaw, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		t = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				return r
			}
			return -1
		}, t)
		if t != "" {
			tags = append(tags, t)
		}
	}

	homepage := prompt(
		"Homepage URL (GitHub, website, or leave blank):",
		"e.g. https://github.com/yourname/"+site,
		false,
	)

	repository := prompt(
		"Repository URL (where source code lives, or leave blank):",
		"e.g. https://github.com/yourname/"+site+".git",
		false,
	)

	// Manual exports override
	exportStr := prompt(
		fmt.Sprintf("Exported probe names (auto-detected: %s):", strings.Join(exports, ", ")),
		"Press Enter to use auto-detected, or provide a comma-separated list",
		false,
	)
	if exportStr != "" {
		exports = nil
		for _, e := range strings.Split(exportStr, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				exports = append(exports, e)
			}
		}
	}

	// ── Build manifest ────────────────────────────────────────────────────

	now := time.Now().Format(time.RFC3339)
	manifest := PackageManifest{
		Name:        displayName,
		Site:        site,
		Version:     version,
		Description: description,
		LongDesc:    longDesc,
		Author:      author,
		License:     license,
		Usage:       usageExample,
		Tags:        tags,
		Homepage:    homepage,
		Repository:  repository,
		MinFortress: VERSION,
		Files:       frtFiles,
		Exports:     exports,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// ── Confirmation ──────────────────────────────────────────────────────

	fmt.Printf("\n  ─────────────────────────────────────────────────\n")
	fmt.Printf("  Library Summary:\n\n")
	fmt.Printf("    Name         : %s (%s)\n", displayName, site)
	fmt.Printf("    Version      : %s\n", version)
	fmt.Printf("    Author       : %s\n", author)
	fmt.Printf("    License      : %s\n", license)
	fmt.Printf("    Description  : %s\n", description)
	fmt.Printf("    Files        : %s\n", strings.Join(frtFiles, ", "))
	fmt.Printf("    Exports      : %s\n", strings.Join(exports, ", "))
	fmt.Printf("    Tags         : %s\n", strings.Join(tags, ", "))
	fmt.Printf("\n  Confirm creation? [Y/n]: ")
	conf, _ := reader.ReadString('\n')
	conf = strings.TrimSpace(strings.ToLower(conf))
	if conf == "n" || conf == "no" {
		fmt.Println("  Aborted.")
		return
	}

	// ── Write output files ────────────────────────────────────────────────

	outName := site + "-" + version + ".frtpkg"
	if err := writeFrtpkg(outName, manifest, frtFiles); err != nil {
		fmt.Printf("  ✖ Failed to write package: %v\n", err)
		return
	}

	// Also write fortress.pkg manifest locally
	manData, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile("fortress.pkg", manData, 0644)

	// Auto-install locally
	localDir := filepath.Join(libsDir(), site)
	os.MkdirAll(localDir, 0755)
	_ = os.WriteFile(filepath.Join(localDir, "fortress.pkg"), manData, 0644)
	for _, f := range frtFiles {
		data, err := os.ReadFile(f)
		if err == nil {
			os.WriteFile(filepath.Join(localDir, filepath.Base(f)), data, 0644)
		}
	}

	reg.Packages[site] = RegistryEntry{
		Name:        displayName,
		Site:        site,
		Version:     version,
		Description: description,
		Author:      author,
		License:     license,
		InstalledAt: now,
		LibDir:      localDir,
	}
	saveRegistry(reg)

	// ── Done ──────────────────────────────────────────────────────────────

	fmt.Printf("\n  ✔ Package created  : %s\n", outName)
	fmt.Printf("  ✔ Manifest written : fortress.pkg\n")
	fmt.Printf("  ✔ Auto-installed   : %s\n", localDir)
	fmt.Printf("\n  ─────────────────────────────────────────────────\n")
	fmt.Printf("  Share your library:\n\n")
	fmt.Printf("    1. Upload %s to GitHub / your website\n", outName)
	fmt.Printf("    2. Other users can install with:\n")
	fmt.Printf("         fortress get file=%s\n", outName)
	fmt.Printf("    3. Or copy the .frtpkg to their machine and run the same\n")
	fmt.Printf("\n  Use in scripts:\n")
	fmt.Printf("    import %s\n", site)
	if len(exports) > 0 {
		fmt.Printf("    %s.%s(\"arg\")\n", site, exports[0])
	}
	fmt.Println()
}

// ─── CMD: fortress list ───────────────────────────────────────────────────────

func cmdList() {
	reg := loadRegistry()
	if len(reg.Packages) == 0 {
		fmt.Println("  No libraries installed.")
		fmt.Printf("  Install one with: fortress get site=<library-name>\n")
		return
	}

	// Sort by name
	var names []string
	for n := range reg.Packages {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Printf("\n  ╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("  ║  Installed Fortress Libraries  (%d total)%s║\n",
		len(names), strings.Repeat(" ", 20-len(fmt.Sprintf("%d", len(names)))))
	fmt.Printf("  ╚══════════════════════════════════════════════════════════════╝\n\n")

	for _, n := range names {
		p := reg.Packages[n]
		fmt.Printf("  ⬡  %-24s  v%-8s  %s\n", p.Site, p.Version, p.Name)
		fmt.Printf("     %-24s  by %s\n", p.License, p.Author)
		fmt.Printf("     %s\n", truncate(p.Description, 60))
		fmt.Printf("     import %s\n\n", p.Site)
	}
}

// ─── CMD: fortress remove site=<name> ────────────────────────────────────────

func cmdRemove(args []string) {
	site := ""
	for _, a := range args {
		if strings.HasPrefix(a, "site=") {
			site = strings.TrimPrefix(a, "site=")
		}
	}
	if site == "" {
		fmt.Println("  ✖ Usage: fortress remove site=<library-name>")
		return
	}
	site = strings.ToLower(strings.TrimSpace(site))
	reg := loadRegistry()
	entry, exists := reg.Packages[site]
	if !exists {
		fmt.Printf("  ✖ Library '%s' is not installed.\n", site)
		return
	}

	fmt.Printf("  Remove library '%s' v%s by %s? [y/N]: ", site, entry.Version, entry.Author)
	var ans string
	fmt.Scanln(&ans)
	if strings.ToLower(strings.TrimSpace(ans)) != "y" {
		fmt.Println("  Aborted.")
		return
	}

	if entry.LibDir != "" {
		os.RemoveAll(entry.LibDir)
	}
	delete(reg.Packages, site)
	saveRegistry(reg)
	fmt.Printf("  ✔ Removed '%s'.\n", site)
}

// ─── CMD: fortress info site=<name> ──────────────────────────────────────────

func cmdInfo(args []string) {
	site := ""
	for _, a := range args {
		if strings.HasPrefix(a, "site=") {
			site = strings.TrimPrefix(a, "site=")
		}
	}
	if site == "" {
		fmt.Println("  ✖ Usage: fortress info site=<library-name>")
		return
	}
	site = strings.ToLower(strings.TrimSpace(site))
	reg := loadRegistry()
	entry, exists := reg.Packages[site]
	if !exists {
		fmt.Printf("  ✖ Library '%s' is not installed. Install with: fortress get site=%s\n", site, site)
		return
	}

	// Try to load full manifest from disk
	manPath := filepath.Join(entry.LibDir, "fortress.pkg")
	var manifest PackageManifest
	if data, err := os.ReadFile(manPath); err == nil {
		json.Unmarshal(data, &manifest)
	}

	fmt.Printf("\n  ⬡  %s  (site: %s)\n", entry.Name, entry.Site)
	fmt.Printf("  ─────────────────────────────────────────────────\n")
	fmt.Printf("  Version      : %s\n", entry.Version)
	fmt.Printf("  Author       : %s\n", entry.Author)
	fmt.Printf("  License      : %s\n", entry.License)
	fmt.Printf("  Installed    : %s\n", entry.InstalledAt)
	fmt.Printf("  Location     : %s\n", entry.LibDir)
	fmt.Printf("\n  Description:\n  %s\n", entry.Description)

	if manifest.LongDesc != "" {
		fmt.Printf("\n  Details:\n  %s\n", manifest.LongDesc)
	}
	if manifest.Usage != "" {
		fmt.Printf("\n  Usage:\n  %s\n", manifest.Usage)
	}
	if len(manifest.Exports) > 0 {
		fmt.Printf("\n  Exports: %s\n", strings.Join(manifest.Exports, ", "))
	}
	if len(manifest.Tags) > 0 {
		fmt.Printf("  Tags   : %s\n", strings.Join(manifest.Tags, ", "))
	}
	if manifest.Homepage != "" {
		fmt.Printf("  Home   : %s\n", manifest.Homepage)
	}
	if manifest.Repository != "" {
		fmt.Printf("  Repo   : %s\n", manifest.Repository)
	}

	// List files
	if entry.LibDir != "" {
		if files, err := os.ReadDir(entry.LibDir); err == nil {
			var frtNames []string
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".frt") {
					frtNames = append(frtNames, f.Name())
				}
			}
			if len(frtNames) > 0 {
				fmt.Printf("  Files  : %s\n", strings.Join(frtNames, ", "))
			}
		}
	}

	fmt.Printf("\n  Import in script:\n    import %s\n\n", site)
}

// ─── Import Execution (called by interpreter) ─────────────────────────────────

// LoadLibrary resolves an import statement, finds the library on disk,
// reads all .frt files, parses them, and returns the AST nodes.
// The interpreter then evaluates them in a child environment and binds
// the result to the alias in the current scope.
func LoadLibrary(module, alias string) ([]Node, error) {
	site := strings.ToLower(strings.TrimSpace(module))
	reg := loadRegistry()

	entry, exists := reg.Packages[site]
	if !exists {
		return nil, fmt.Errorf(
			"library '%s' is not installed.\n  Install with: fortress get site=%s",
			module, site,
		)
	}

	libDir := entry.LibDir
	if libDir == "" {
		libDir = filepath.Join(libsDir(), site)
	}

	// Find all .frt files in the library directory
	files, err := os.ReadDir(libDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read library directory '%s': %v", libDir, err)
	}

	var allStatements []Node
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".frt") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(libDir, f.Name()))
		if err != nil {
			continue
		}

		lexer := NewLexer(string(data))
		tokens, lexErr := lexer.Tokenize()
		if lexErr != nil {
			return nil, fmt.Errorf("lex error in library '%s' (%s): %v", module, f.Name(), lexErr)
		}
		parser := NewParser(tokens)
		prog, parseErr := parser.Parse()
		if parseErr != nil {
			return nil, fmt.Errorf("parse error in library '%s' (%s): %v", module, f.Name(), parseErr)
		}
		allStatements = append(allStatements, prog.Statements...)
	}

	if len(allStatements) == 0 {
		return nil, fmt.Errorf("library '%s' has no .frt files", module)
	}

	return allStatements, nil
}

// ─── .frtpkg Archive Format ───────────────────────────────────────────────────
// A .frtpkg is a ZIP archive containing:
//   fortress.pkg   — PackageManifest JSON
//   *.frt          — Fortress source files

func writeFrtpkg(outPath string, manifest PackageManifest, frtFiles []string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	// Write manifest
	manData, _ := json.MarshalIndent(manifest, "", "  ")
	mw, err := w.Create("fortress.pkg")
	if err != nil {
		return err
	}
	mw.Write(manData)

	// Write each .frt file
	for _, src := range frtFiles {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("cannot read %s: %v", src, err)
		}
		fw, err := w.Create(filepath.Base(src))
		if err != nil {
			return err
		}
		fw.Write(data)
	}
	return nil
}

func readFrtpkg(path string) (PackageManifest, map[string][]byte, error) {
	var manifest PackageManifest
	files := map[string][]byte{}

	r, err := zip.OpenReader(path)
	if err != nil {
		return manifest, nil, fmt.Errorf("not a valid .frtpkg file: %v", err)
	}
	defer r.Close()

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()

		if f.Name == "fortress.pkg" {
			if err := json.Unmarshal(data, &manifest); err != nil {
				return manifest, nil, fmt.Errorf("corrupt fortress.pkg: %v", err)
			}
		} else if strings.HasSuffix(f.Name, ".frt") {
			files[filepath.Base(f.Name)] = data
		}
	}

	if manifest.Site == "" {
		return manifest, nil, fmt.Errorf("fortress.pkg is missing or has no 'site' field")
	}
	return manifest, files, nil
}

// ─── Remote fetch ─────────────────────────────────────────────────────────────
// Tries to download a library from known public sources.
// Resolution order:
//   1. CzaxStudio/Fortress GitHub Releases (official libraries)
//   2. Raw file in CzaxStudio/Fortress main branch
//   3. Community convention: github.com/<site>-frt/<site> (user-published libs)
//   4. Author's own repo if they followed the naming convention

func fetchPackage(site, version string) (PackageManifest, map[string][]byte, error) {
	versionedPkg := site + "-" + version + ".frtpkg"
	latestPkg := site + "-1.0.0.frtpkg" // common default
	simplePkg := site + ".frtpkg"

	candidates := []string{
		// ── Official CzaxStudio/Fortress release assets ──────────────────
		fmt.Sprintf("https://github.com/CzaxStudio/Fortress/releases/latest/download/%s", versionedPkg),
		fmt.Sprintf("https://github.com/CzaxStudio/Fortress/releases/latest/download/%s", simplePkg),
		// ── Raw files in the main branch (works before a formal release) ─
		fmt.Sprintf("https://raw.githubusercontent.com/CzaxStudio/Fortress/main/libs/%s/%s", site, simplePkg),
		fmt.Sprintf("https://raw.githubusercontent.com/CzaxStudio/Fortress/main/%s", versionedPkg),
		fmt.Sprintf("https://raw.githubusercontent.com/CzaxStudio/Fortress/main/%s", simplePkg),
		// ── Community convention: github.com/<site>-frt/<site> ───────────
		// Library authors can publish by creating a repo named <site>-frt
		fmt.Sprintf("https://github.com/%s-frt/%s/releases/latest/download/%s", site, site, simplePkg),
		fmt.Sprintf("https://raw.githubusercontent.com/%s-frt/%s/main/%s", site, site, simplePkg),
	}

	// For versioned requests replace latest with the specific tag
	if version != "latest" {
		candidates = append([]string{
			fmt.Sprintf("https://github.com/CzaxStudio/Fortress/releases/download/v%s/%s", version, versionedPkg),
			fmt.Sprintf("https://github.com/CzaxStudio/Fortress/releases/download/v%s/%s", version, simplePkg),
		}, candidates...)
		_ = latestPkg
	}

	client := &http.Client{Timeout: 15 * time.Second}
	for _, url := range candidates {
		fmt.Printf("     Trying %s ...\n", url)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		manifest, files, err := readFrtpkg_bytes(data)
		if err != nil {
			continue
		}

		fmt.Printf("     Found: %s v%s by %s\n", manifest.Name, manifest.Version, manifest.Author)
		return manifest, files, nil
	}

	return PackageManifest{}, nil,
		fmt.Errorf("library '%s' not found.\n\n"+
			"  For official libraries, make sure the .frtpkg files are uploaded to:\n"+
			"    https://github.com/CzaxStudio/Fortress/releases\n\n"+
			"  To install from a local file:\n"+
			"    fortress get file=cryptoutils-1.0.0.frtpkg\n\n"+
			"  To publish your own library so others can install it with 'fortress get site=%s':\n"+
			"    1. Create a GitHub repo named '%s-frt'\n"+
			"    2. Add your .frtpkg file to the repo root\n"+
			"    3. Users can then run: fortress get site=%s", site, site, site, site)
}

func readFrtpkg_bytes(data []byte) (PackageManifest, map[string][]byte, error) {
	var manifest PackageManifest
	files := map[string][]byte{}

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return manifest, nil, err
	}

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		fdata, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "fortress.pkg" {
			json.Unmarshal(fdata, &manifest)
		} else if strings.HasSuffix(f.Name, ".frt") {
			files[filepath.Base(f.Name)] = fdata
		}
	}
	if manifest.Site == "" {
		return manifest, nil, fmt.Errorf("invalid package: missing site field")
	}
	return manifest, files, nil
}

// ─── Export Scanner ───────────────────────────────────────────────────────────
// Scans .frt source files and extracts all top-level probe names.

var probeDefRe = regexp.MustCompile(`(?m)^\s*probe\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

func scanExports(files []string) []string {
	seen := map[string]bool{}
	var exports []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		matches := probeDefRe.FindAllSubmatch(data, -1)
		for _, m := range matches {
			name := string(m[1])
			// Skip internal helpers (lowercase single-word names common in demo.frt)
			if !seen[name] {
				seen[name] = true
				exports = append(exports, name)
			}
		}
	}
	sort.Strings(exports)
	return exports
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
