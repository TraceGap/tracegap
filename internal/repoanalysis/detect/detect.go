package detect

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

type RepoType string

const (
	RepoTypeUnknown RepoType = "unknown"
	RepoTypeGo      RepoType = "go"
)

type Limits struct {
	MaxFiles int
}

type Result struct {
	Type          RepoType
	GoModuleRoots []string
	Limited       bool
}

func DefaultLimits() Limits {
	return Limits{MaxFiles: 5000}
}

var errLimitReached = errors.New("repo detection file limit reached")

func DetectRepoType(repoPath string, limits Limits) (Result, error) {
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = DefaultLimits().MaxFiles
	}

	result := Result{Type: RepoTypeUnknown}
	fileCount := 0

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		fileCount++
		if fileCount > limits.MaxFiles {
			result.Limited = true
			return errLimitReached
		}

		if d.Name() != "go.mod" {
			return nil
		}

		relDir, relErr := filepath.Rel(repoPath, filepath.Dir(path))
		if relErr != nil {
			return nil
		}
		relDir = filepath.ToSlash(relDir)
		if relDir == "" {
			relDir = "."
		}
		result.GoModuleRoots = append(result.GoModuleRoots, relDir)
		result.Type = RepoTypeGo
		return nil
	})

	if err != nil && !errors.Is(err, errLimitReached) {
		return Result{}, err
	}

	sort.Strings(result.GoModuleRoots)
	return result, nil
}

func shouldSkipDir(name string) bool {
	name = strings.TrimSpace(name)
	switch name {
	case ".git", "vendor", "node_modules", "dist", "build", "tmp":
		return true
	default:
		return false
	}
}
