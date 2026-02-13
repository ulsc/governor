package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"governor/internal/model"
	"governor/internal/safefile"
)

type StageOptions struct {
	InputPath string
	OutDir    string
	MaxFiles  int
	MaxBytes  int64
}

type StageResult struct {
	InputType     string
	InputPath     string
	WorkspacePath string
	Manifest      model.InputManifest
	Cleanup       func() error
}

const (
	dirPerm  = 0o700
	filePerm = 0o600
)

var skipDirNames = map[string]struct{}{
	".git": {}, ".governor": {}, "bin": {}, "node_modules": {}, "vendor": {}, "dist": {}, "build": {}, ".next": {}, "target": {}, "coverage": {},
	".aws": {}, ".ssh": {}, ".gnupg": {},
}

var skipFileExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".pdf": {}, ".zip": {}, ".gz": {}, ".tar": {}, ".tgz": {},
	".mp3": {}, ".wav": {}, ".mp4": {}, ".mov": {}, ".avi": {}, ".woff": {}, ".woff2": {}, ".ttf": {},
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".class": {}, ".jar": {},
	".pem": {}, ".key": {}, ".p12": {}, ".pfx": {}, ".crt": {},
}

var skipFileNames = map[string]struct{}{
	".DS_Store": {},
}

func Stage(opts StageOptions) (StageResult, error) {
	if strings.TrimSpace(opts.InputPath) == "" {
		return StageResult{}, errors.New("input path is required")
	}
	if opts.MaxFiles <= 0 {
		return StageResult{}, errors.New("max files must be > 0")
	}
	if opts.MaxBytes <= 0 {
		return StageResult{}, errors.New("max bytes must be > 0")
	}

	inAbs, err := filepath.Abs(opts.InputPath)
	if err != nil {
		return StageResult{}, fmt.Errorf("resolve input path: %w", err)
	}
	st, err := os.Stat(inAbs)
	if err != nil {
		return StageResult{}, fmt.Errorf("stat input path: %w", err)
	}

	workspace := filepath.Join(opts.OutDir, "workspace")
	if err := os.MkdirAll(workspace, dirPerm); err != nil {
		return StageResult{}, fmt.Errorf("create workspace: %w", err)
	}
	workspaceAbs, err := filepath.Abs(workspace)
	if err != nil {
		return StageResult{}, fmt.Errorf("resolve workspace path: %w", err)
	}
	outAbs, err := filepath.Abs(opts.OutDir)
	if err != nil {
		return StageResult{}, fmt.Errorf("resolve output path: %w", err)
	}

	res := StageResult{
		InputPath:     inAbs,
		WorkspacePath: workspaceAbs,
		Cleanup: func() error {
			if err := validateCleanupWorkspace(workspaceAbs, outAbs); err != nil {
				return err
			}
			return os.RemoveAll(workspaceAbs)
		},
	}

	inputType := "folder"
	if !st.IsDir() {
		if !strings.EqualFold(filepath.Ext(inAbs), ".zip") {
			return StageResult{}, fmt.Errorf("input must be a folder or .zip file")
		}
		inputType = "zip"
	}
	res.InputType = inputType

	manifest := model.InputManifest{
		RootPath:        workspace,
		InputPath:       inAbs,
		InputType:       inputType,
		SkippedByReason: map[string]int{},
		GeneratedAt:     time.Now().UTC(),
		Files:           make([]model.ManifestFile, 0, min(1024, opts.MaxFiles)),
	}

	if st.IsDir() {
		if err := stageFolderToWorkspace(inAbs, workspace, &manifest, opts.MaxFiles, opts.MaxBytes); err != nil {
			return StageResult{}, err
		}
	} else {
		if err := stageZipToWorkspace(inAbs, workspace, &manifest, opts.MaxFiles, opts.MaxBytes); err != nil {
			return StageResult{}, err
		}
	}

	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	res.Manifest = manifest

	return res, nil
}

func stageFolderToWorkspace(srcRoot string, dstRoot string, manifest *model.InputManifest, maxFiles int, maxBytes int64) error {
	return filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == srcRoot {
			return nil
		}

		rel, relErr := filepath.Rel(srcRoot, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		name := d.Name()

		if d.Type()&os.ModeSymlink != 0 {
			manifest.SkippedByReason["symlink"]++
			manifest.SkippedFiles++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if _, skip := skipDirNames[name]; skip {
				manifest.SkippedByReason["skip_dir"]++
				return filepath.SkipDir
			}
			return nil
		}

		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			manifest.SkippedByReason["symlink"]++
			manifest.SkippedFiles++
			return nil
		}
		if !info.Mode().IsRegular() {
			manifest.SkippedByReason["non_regular"]++
			manifest.SkippedFiles++
			return nil
		}
		if hardLinkCount(info) > 1 {
			manifest.SkippedByReason["hardlink"]++
			manifest.SkippedFiles++
			return nil
		}

		if reason, skip := skipFile(name, rel, info.Size(), info.Mode()); skip {
			manifest.SkippedByReason[reason]++
			manifest.SkippedFiles++
			return nil
		}

		targetPath, err := workspaceTargetPath(dstRoot, rel)
		if err != nil {
			return err
		}
		if manifest.IncludedFiles+1 > maxFiles {
			return fmt.Errorf("included file count exceeds limit: %d > %d", manifest.IncludedFiles+1, maxFiles)
		}

		copied, err := copyFileWithLimit(path, targetPath, maxBytes-manifest.IncludedBytes, info, srcRoot)
		if err != nil {
			return err
		}

		manifest.Files = append(manifest.Files, model.ManifestFile{Path: rel, Size: copied})
		manifest.IncludedFiles++
		manifest.IncludedBytes += copied
		return nil
	})
}

func skipFile(name string, rel string, size int64, mode os.FileMode) (reason string, skip bool) {
	if mode&os.ModeSymlink != 0 {
		return "symlink", true
	}
	if isSensitiveFileName(name) {
		return "skip_secret", true
	}
	if _, ok := skipFileNames[name]; ok {
		return "skip_name", true
	}
	if size == 0 {
		return "empty", true
	}
	ext := strings.ToLower(filepath.Ext(name))
	if _, ok := skipFileExts[ext]; ok {
		return "skip_ext", true
	}
	if hasSkippedDirComponent(rel) {
		return "skip_dir", true
	}
	return "", false
}

func isSensitiveFileName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	switch name {
	case ".env", ".npmrc", ".netrc", ".pypirc", "id_rsa", "id_ed25519":
		return true
	}
	if strings.HasPrefix(name, ".env.") {
		return true
	}
	if strings.HasPrefix(name, "secrets.") {
		return true
	}
	return false
}

func hasSkippedDirComponent(rel string) bool {
	parts := strings.Split(filepath.ToSlash(strings.TrimSpace(rel)), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if _, ok := skipDirNames[part]; ok {
			return true
		}
	}
	return false
}

func workspaceTargetPath(dstRoot string, rel string) (string, error) {
	cleanRel := filepath.Clean(filepath.FromSlash(rel))
	if cleanRel == "." || cleanRel == "" {
		return "", fmt.Errorf("invalid target relative path")
	}
	if strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) || cleanRel == ".." {
		return "", fmt.Errorf("target path escapes workspace: %s", rel)
	}

	targetPath := filepath.Join(dstRoot, cleanRel)
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve workspace target: %w", err)
	}
	rootAbs, err := filepath.Abs(dstRoot)
	if err != nil {
		return "", fmt.Errorf("resolve workspace root: %w", err)
	}
	if !strings.HasPrefix(targetAbs, rootAbs+string(filepath.Separator)) && targetAbs != rootAbs {
		return "", fmt.Errorf("target path escapes workspace root: %s", rel)
	}
	return targetAbs, nil
}

func validateCleanupWorkspace(workspaceAbs string, outAbs string) error {
	workspaceAbs = filepath.Clean(strings.TrimSpace(workspaceAbs))
	outAbs = filepath.Clean(strings.TrimSpace(outAbs))
	if workspaceAbs == "" || workspaceAbs == "." {
		return fmt.Errorf("invalid workspace cleanup path")
	}
	if filepath.Base(workspaceAbs) != "workspace" {
		return fmt.Errorf("refusing cleanup for non-workspace path: %s", workspaceAbs)
	}
	if outAbs == "" || outAbs == "." {
		return fmt.Errorf("invalid output root for cleanup")
	}
	prefix := outAbs + string(filepath.Separator)
	if workspaceAbs != outAbs && !strings.HasPrefix(workspaceAbs, prefix) {
		return fmt.Errorf("workspace path escapes output root: %s", workspaceAbs)
	}
	return nil
}

func copyFileWithLimit(srcPath string, dstPath string, byteBudget int64, expected os.FileInfo, srcRoot string) (int64, error) {
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		return 0, fmt.Errorf("resolve source file %s: %w", srcPath, err)
	}
	rootAbs, err := filepath.Abs(srcRoot)
	if err != nil {
		return 0, fmt.Errorf("resolve source root %s: %w", srcRoot, err)
	}
	if !pathWithinRoot(srcAbs, rootAbs) {
		return 0, fmt.Errorf("source file escapes root: %s", srcPath)
	}

	if expected == nil {
		return 0, fmt.Errorf("missing source metadata for %s", srcPath)
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return 0, fmt.Errorf("source file must be regular and not symlink: %s", srcPath)
	}
	if hardLinkCount(expected) > 1 {
		return 0, fmt.Errorf("hard-linked source file is not allowed: %s", srcPath)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("open source file %s: %w", srcPath, err)
	}
	defer src.Close()

	opened, err := src.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat source file %s: %w", srcPath, err)
	}
	if opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() {
		return 0, fmt.Errorf("source file must be regular and not symlink: %s", srcPath)
	}
	if hardLinkCount(opened) > 1 {
		return 0, fmt.Errorf("hard-linked source file is not allowed: %s", srcPath)
	}
	if !os.SameFile(expected, opened) {
		return 0, fmt.Errorf("source file changed during copy: %s", srcPath)
	}

	return copyReaderToPathWithLimit(src, dstPath, byteBudget)
}

func copyReaderToPathWithLimit(src io.Reader, dstPath string, byteBudget int64) (int64, error) {
	if byteBudget <= 0 {
		return 0, fmt.Errorf("included byte size exceeds limit: no remaining byte budget")
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), dirPerm); err != nil {
		return 0, fmt.Errorf("create workspace parent dir: %w", err)
	}

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm)
	if err != nil {
		return 0, fmt.Errorf("create workspace file %s: %w", dstPath, err)
	}
	defer dst.Close()

	limited := &io.LimitedReader{R: src, N: byteBudget + 1}
	n, err := io.Copy(dst, limited)
	if err != nil {
		_ = os.Remove(dstPath)
		return 0, fmt.Errorf("copy workspace file %s: %w", dstPath, err)
	}
	if n > byteBudget {
		_ = os.Remove(dstPath)
		return 0, fmt.Errorf("included byte size exceeds limit: %d > %d", n, byteBudget)
	}
	if n == 0 {
		_ = os.Remove(dstPath)
		return 0, fmt.Errorf("included byte size exceeds limit: zero-size files are not allowed")
	}
	return n, nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func WriteManifest(path string, manifest model.InputManifest) error {
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, b, filePerm); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func hardLinkCount(info os.FileInfo) uint64 {
	if info == nil || info.Sys() == nil {
		return 0
	}
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() {
		return 0
	}
	field := v.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := field.Int()
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

func pathWithinRoot(path string, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}
