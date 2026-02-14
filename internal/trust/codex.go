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

type AIBinary struct {
	RequestedPath string
	ResolvedPath  string
	Version       string
	SHA256        string
	IsDefaultName bool
}

// ResolveAIBinary canonicalizes and attests the configured AI executable before use.
func ResolveAIBinary(ctx context.Context, requested string, allowCustom bool) (AIBinary, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = "codex"
	}

	isDefaultName := requested == "codex"
	if !isDefaultName && !allowCustom {
		return AIBinary{}, fmt.Errorf("custom ai binary is disabled by default; use --allow-custom-ai-bin for non-production/mock runs")
	}

	lookedUp, err := exec.LookPath(requested)
	if err != nil {
		return AIBinary{}, fmt.Errorf("resolve ai binary %q: %w", requested, err)
	}

	absPath, err := filepath.Abs(lookedUp)
	if err != nil {
		return AIBinary{}, fmt.Errorf("resolve absolute ai path: %w", err)
	}

	resolved := absPath
	if eval, evalErr := filepath.EvalSymlinks(absPath); evalErr == nil && strings.TrimSpace(eval) != "" {
		resolved = eval
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return AIBinary{}, fmt.Errorf("stat ai binary: %w", err)
	}
	if info.IsDir() {
		return AIBinary{}, fmt.Errorf("ai path is a directory: %s", resolved)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return AIBinary{}, fmt.Errorf("ai path is not executable: %s", resolved)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return AIBinary{}, fmt.Errorf("ai binary is group/world writable and not trusted: %s", resolved)
	}
	if isDefaultName {
		cwd, cwdErr := os.Getwd()
		if cwdErr == nil {
			cwdAbs, absErr := filepath.Abs(cwd)
			if absErr == nil {
				if strings.HasPrefix(resolved, cwdAbs+string(filepath.Separator)) || resolved == cwdAbs {
					return AIBinary{}, fmt.Errorf("refusing default ai binary resolved from current workspace: %s", resolved)
				}
			}
		}
	}

	hash, err := fileSHA256(resolved)
	if err != nil {
		return AIBinary{}, fmt.Errorf("hash ai binary: %w", err)
	}

	version, err := readVersion(ctx, resolved)
	if err != nil {
		return AIBinary{}, err
	}

	return AIBinary{
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
	defer func() { _ = f.Close() }()

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
		return "", fmt.Errorf("read ai binary version: %w", err)
	}

	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", fmt.Errorf("ai --version returned empty output")
	}
	if i := strings.IndexByte(version, '\n'); i >= 0 {
		version = strings.TrimSpace(version[:i])
	}
	return version, nil
}

// ResolveCodexBinary is a compatibility wrapper around ResolveAIBinary.
func ResolveCodexBinary(ctx context.Context, requested string, allowCustom bool) (AIBinary, error) {
	return ResolveAIBinary(ctx, requested, allowCustom)
}

// CodexBinary is a compatibility alias for AIBinary.
type CodexBinary = AIBinary
