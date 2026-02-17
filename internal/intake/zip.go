package intake

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"governor/internal/model"
)

const (
	zipEntryLimitMultiplier    = 20
	maxCompressionRatio        = 100
	maxZipEntryUncompressBytes = 1024 * 1024 * 1024 // 1 GB per entry
	zipExtractionTimeout       = 5 * time.Minute
)

func stageZipToWorkspace(zipPath string, destDir string, manifest *model.InputManifest, maxFiles int, maxBytes int64, ignoreRules *IgnoreRules) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve destination: %w", err)
	}
	maxEntries := maxFiles * zipEntryLimitMultiplier
	if maxEntries < maxFiles {
		maxEntries = maxFiles
	}
	if maxEntries < 1000 {
		maxEntries = 1000
	}
	if len(r.File) > maxEntries {
		return fmt.Errorf("zip entry count exceeds limit: %d > %d", len(r.File), maxEntries)
	}

	// Pre-scan: check compression ratios and individual entry sizes.
	var projectedIncludedBytes int64
	for _, f := range r.File {
		cleanName, err := cleanZipEntryName(f.Name)
		if err != nil {
			return err
		}
		if cleanName == "" {
			continue
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(cleanName, "/") {
			continue
		}

		uncompressed := f.UncompressedSize64
		compressed := f.CompressedSize64

		// Check per-entry uncompressed size limit.
		if uncompressed > maxZipEntryUncompressBytes {
			return fmt.Errorf("zip entry %s uncompressed size exceeds limit: %d > %d", cleanName, uncompressed, maxZipEntryUncompressBytes)
		}

		// Check compression ratio (zip bomb detection).
		if compressed > 0 && uncompressed/compressed > maxCompressionRatio {
			return fmt.Errorf("zip entry %s has suspicious compression ratio: %d:1 (limit %d:1)", cleanName, uncompressed/compressed, maxCompressionRatio)
		}

		if reason, skip := skipFile(filepath.Base(cleanName), cleanName, f.FileInfo().Size(), f.Mode()); skip {
			if reason == "skip_dir" {
				continue
			}
			continue
		}
		projectedIncludedBytes += f.FileInfo().Size()
		if projectedIncludedBytes > maxBytes {
			return fmt.Errorf("zip included byte size exceeds limit before extraction: %d > %d", projectedIncludedBytes, maxBytes)
		}
	}

	// Extract with timeout context.
	ctx, cancel := context.WithTimeout(context.Background(), zipExtractionTimeout)
	defer cancel()

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return fmt.Errorf("zip extraction timed out after %s", zipExtractionTimeout)
		default:
		}
		if err := extractZipFile(destAbs, f, manifest, maxFiles, maxBytes, ignoreRules); err != nil {
			return err
		}
	}

	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return nil
}

func extractZipFile(destAbs string, f *zip.File, manifest *model.InputManifest, maxFiles int, maxBytes int64, ignoreRules *IgnoreRules) error {
	cleanName, err := cleanZipEntryName(f.Name)
	if err != nil {
		return err
	}
	if cleanName == "" {
		return nil
	}

	mode := f.Mode()
	if mode&os.ModeSymlink != 0 {
		manifest.SkippedByReason["symlink"]++
		manifest.SkippedFiles++
		return nil
	}

	if f.FileInfo().IsDir() || strings.HasSuffix(cleanName, "/") {
		if hasSkippedDirComponent(cleanName) {
			manifest.SkippedByReason["skip_dir"]++
			return nil
		}
		if ignoreRules.ShouldIgnore(cleanName, true) {
			manifest.SkippedByReason["governorignore"]++
			return nil
		}
		targetPath, err := workspaceTargetPath(destAbs, cleanName)
		if err != nil {
			return err
		}
		return os.MkdirAll(targetPath, dirPerm)
	}

	if reason, skip := skipFile(filepath.Base(cleanName), cleanName, f.FileInfo().Size(), mode); skip {
		manifest.SkippedByReason[reason]++
		manifest.SkippedFiles++
		if reason == "security_relevant_excluded" {
			manifest.SecurityRelevantSkipped++
		}
		return nil
	}

	if ignoreRules.ShouldIgnore(cleanName, false) {
		manifest.SkippedByReason["governorignore"]++
		manifest.SkippedFiles++
		return nil
	}

	if manifest.IncludedFiles+1 > maxFiles {
		return fmt.Errorf("included file count exceeds limit: %d > %d", manifest.IncludedFiles+1, maxFiles)
	}

	targetAbs, err := workspaceTargetPath(destAbs, cleanName)
	if err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	copied, err := copyReaderToPathWithLimit(rc, targetAbs, maxBytes-manifest.IncludedBytes)
	if err != nil {
		return fmt.Errorf("extract zip entry %s: %w", f.Name, err)
	}

	manifest.Files = append(manifest.Files, model.ManifestFile{Path: cleanName, Size: copied})
	manifest.IncludedFiles++
	manifest.IncludedBytes += copied

	return nil
}

func cleanZipEntryName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	cleanName := filepath.ToSlash(filepath.Clean(name))
	if cleanName == "." || cleanName == "" {
		return "", nil
	}
	if strings.HasPrefix(cleanName, "../") || strings.Contains(cleanName, "/../") || cleanName == ".." {
		return "", fmt.Errorf("zip contains unsafe relative path: %s", name)
	}
	if strings.HasPrefix(cleanName, "/") || filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("zip contains absolute path: %s", name)
	}
	return cleanName, nil
}
