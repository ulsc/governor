package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnsureFreshDir creates a new directory and fails if it already exists.
// It rejects symlinked parent/target paths.
func EnsureFreshDir(path string, perm os.FileMode) (string, error) {
	abs, err := cleanAbsPath(path)
	if err != nil {
		return "", err
	}

	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, perm); err != nil {
		return "", fmt.Errorf("create parent directory: %w", err)
	}
	if err := ensureDirPathNoSymlink(parent); err != nil {
		return "", err
	}

	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing symlinked output directory: %s", abs)
		}
		return "", fmt.Errorf("output directory already exists: %s", abs)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat output directory: %w", err)
	}

	if err := os.Mkdir(abs, perm); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	if err := ensureDirPathNoSymlink(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// EnsureDir ensures a directory exists, is not symlinked, and can optionally be empty.
func EnsureDir(path string, perm os.FileMode, requireEmpty bool) (string, error) {
	abs, err := cleanAbsPath(path)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(abs, perm); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}
	if err := ensureDirPathNoSymlink(abs); err != nil {
		return "", err
	}
	if requireEmpty {
		entries, err := os.ReadDir(abs)
		if err != nil {
			return "", fmt.Errorf("read directory entries: %w", err)
		}
		if len(entries) > 0 {
			return "", fmt.Errorf("output directory must be empty: %s", abs)
		}
	}
	return abs, nil
}

// WriteFileAtomic writes to a temporary file then renames into place.
// This avoids following symlinks on the target path.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	abs, err := cleanAbsPath(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(abs)
	if err := ensureDirPathNoSymlink(dir); err != nil {
		return err
	}

	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked file target: %s", abs)
		}
		if info.IsDir() {
			return fmt.Errorf("refusing directory write target: %s", abs)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat write target: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".governor-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}

	if err := os.Rename(tmpPath, abs); err != nil {
		return fmt.Errorf("replace target file: %w", err)
	}
	cleanup = false
	return nil
}

func cleanAbsPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}
	clean := filepath.Clean(abs)
	if clean == "." {
		return "", fmt.Errorf("invalid path: %s", path)
	}
	return clean, nil
}

func ensureDirPathNoSymlink(path string) error {
	abs, err := cleanAbsPath(path)
	if err != nil {
		return err
	}

	info, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked path: %s", abs)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", abs)
	}
	return nil
}
