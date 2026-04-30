package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectRepoType_GoRootModule(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "go.mod"), "module example.com/root\n")

	result, err := DetectRepoType(repo, DefaultLimits())
	if err != nil {
		t.Fatalf("DetectRepoType returned error: %v", err)
	}
	if result.Type != RepoTypeGo {
		t.Fatalf("expected go repo type, got %q", result.Type)
	}
	if len(result.GoModuleRoots) != 1 || result.GoModuleRoots[0] != "." {
		t.Fatalf("unexpected module roots: %#v", result.GoModuleRoots)
	}
}

func TestDetectRepoType_GoNestedModule(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "services", "checkout", "go.mod"), "module example.com/checkout\n")

	result, err := DetectRepoType(repo, DefaultLimits())
	if err != nil {
		t.Fatalf("DetectRepoType returned error: %v", err)
	}
	if result.Type != RepoTypeGo {
		t.Fatalf("expected go repo type, got %q", result.Type)
	}
	if len(result.GoModuleRoots) != 1 || result.GoModuleRoots[0] != filepath.ToSlash(filepath.Join("services", "checkout")) {
		t.Fatalf("unexpected module roots: %#v", result.GoModuleRoots)
	}
}

func TestDetectRepoType_IgnoresVendorAndNodeModules(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "vendor", "x", "go.mod"), "module bad/vendor\n")
	mustWrite(t, filepath.Join(repo, "node_modules", "pkg", "go.mod"), "module bad/node\n")

	result, err := DetectRepoType(repo, DefaultLimits())
	if err != nil {
		t.Fatalf("DetectRepoType returned error: %v", err)
	}
	if result.Type != RepoTypeUnknown {
		t.Fatalf("expected unknown repo type, got %q", result.Type)
	}
	if len(result.GoModuleRoots) != 0 {
		t.Fatalf("expected no module roots, got %#v", result.GoModuleRoots)
	}
}

func TestDetectRepoType_RespectsFileLimit(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "a.txt"), "a")
	mustWrite(t, filepath.Join(repo, "b.txt"), "b")
	mustWrite(t, filepath.Join(repo, "services", "pay", "go.mod"), "module example.com/pay\n")

	limits := DefaultLimits()
	limits.MaxFiles = 1

	result, err := DetectRepoType(repo, limits)
	if err != nil {
		t.Fatalf("DetectRepoType returned error: %v", err)
	}
	if !result.Limited {
		t.Fatalf("expected Limited=true when scan stops at file limit")
	}
	if result.Type != RepoTypeUnknown {
		t.Fatalf("expected unknown repo type due to limit, got %q", result.Type)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
