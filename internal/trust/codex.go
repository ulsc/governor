package trust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type CodexBinary struct {
	RequestedPath string
	ResolvedPath  string
	Version       string
	SHA256        string
	IsDefaultName bool
}

// ResolveCodexBinary canonicalizes and attests the codex executable before use.
func ResolveCodexBinary(ctx context.Context, requested string, allowCustom bool) (CodexBinary, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = "codex"
	}

	isDefaultName := requested == "codex"
	if !isDefaultName && !allowCustom {
		return CodexBinary{}, fmt.Errorf("custom codex binary is disabled by default; use --allow-custom-codex-bin for non-production/mock runs")
	}

	lookedUp, err := exec.LookPath(requested)
	if err != nil {
		return CodexBinary{}, fmt.Errorf("resolve codex binary %q: %w", requested, err)
	}

	absPath, err := filepath.Abs(lookedUp)
	if err != nil {
		return CodexBinary{}, fmt.Errorf("resolve absolute codex path: %w", err)
	}

	resolved := absPath
	if eval, evalErr := filepath.EvalSymlinks(absPath); evalErr == nil && strings.TrimSpace(eval) != "" {
		resolved = eval
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return CodexBinary{}, fmt.Errorf("stat codex binary: %w", err)
	}
	if info.IsDir() {
		return CodexBinary{}, fmt.Errorf("codex path is a directory: %s", resolved)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return CodexBinary{}, fmt.Errorf("codex path is not executable: %s", resolved)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return CodexBinary{}, fmt.Errorf("codex binary is group/world writable and not trusted: %s", resolved)
	}
	if isDefaultName {
		cwd, cwdErr := os.Getwd()
		if cwdErr == nil {
			cwdAbs, absErr := filepath.Abs(cwd)
			if absErr == nil {
				if strings.HasPrefix(resolved, cwdAbs+string(filepath.Separator)) || resolved == cwdAbs {
					return CodexBinary{}, fmt.Errorf("refusing default codex binary resolved from current workspace: %s", resolved)
				}
			}
		}
	}

	hash, err := fileSHA256(resolved)
	if err != nil {
		return CodexBinary{}, fmt.Errorf("hash codex binary: %w", err)
	}

	version, err := readVersion(ctx, resolved)
	if err != nil {
		return CodexBinary{}, err
	}

	return CodexBinary{
		RequestedPath: requested,
		ResolvedPath:  resolved,
		Version:       version,
		SHA256:        hash,
		IsDefaultName: isDefaultName,
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readVersion(parent context.Context, binPath string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read codex version: %w", err)
	}

	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", fmt.Errorf("codex --version returned empty output")
	}
	if i := strings.IndexByte(version, '\n'); i >= 0 {
		version = strings.TrimSpace(version[:i])
	}
	return version, nil
}
