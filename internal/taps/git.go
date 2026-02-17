package taps

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CloneTap performs a shallow git clone of a tap repository.
func CloneTap(url, destDir string) error {
	cmd := exec.Command("git", "clone", "--depth=1", url, destDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone %s: %w", url, err)
	}
	return nil
}

// UpdateTap performs a git pull in an existing tap directory.
func UpdateTap(tapDir string) error {
	cmd := exec.Command("git", "-C", tapDir, "pull", "--ff-only")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git pull in %s: %w", tapDir, err)
	}
	return nil
}

// ListPacks returns all packs found in a tap directory.
// Packs live under <tapDir>/packs/<packName>/.
func ListPacks(tapDir string) ([]PackMeta, error) {
	packsDir := filepath.Join(tapDir, "packs")
	entries, err := os.ReadDir(packsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read packs dir: %w", err)
	}

	var packs []PackMeta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta := PackMeta{Name: e.Name()}

		packYAML := filepath.Join(packsDir, e.Name(), "pack.yaml")
		if data, err := os.ReadFile(packYAML); err == nil {
			parsePackMeta(data, &meta)
		}
		packs = append(packs, meta)
	}
	return packs, nil
}

func parsePackMeta(data []byte, meta *PackMeta) {
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "name":
			meta.Name = val
		case "description":
			meta.Description = val
		case "version":
			meta.Version = val
		case "author":
			meta.Author = val
		}
	}
}

// FindPack locates a pack by name within a tap directory.
func FindPack(tapDir, packName string) (string, bool) {
	packDir := filepath.Join(tapDir, "packs", packName)
	info, err := os.Stat(packDir)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return packDir, true
}

// CopyPackChecks copies all .check.yaml files from a pack directory to a destination.
func CopyPackChecks(packDir, destDir string) (int, error) {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return 0, fmt.Errorf("create checks dir: %w", err)
	}

	entries, err := os.ReadDir(packDir)
	if err != nil {
		return 0, fmt.Errorf("read pack dir: %w", err)
	}

	copied := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".check.yaml") {
			continue
		}
		src := filepath.Join(packDir, e.Name())
		dst := filepath.Join(destDir, e.Name())
		if err := copyFile(src, dst); err != nil {
			return copied, fmt.Errorf("copy %s: %w", e.Name(), err)
		}
		copied++
	}
	return copied, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
