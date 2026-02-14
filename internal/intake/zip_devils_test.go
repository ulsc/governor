package intake

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// --- Zip Path Traversal Tests ---

func TestCleanZipEntryName_PathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"simple dotdot", "../etc/passwd", true},
		{"nested dotdot", "foo/../../etc/passwd", true},
		{"absolute path", "/etc/passwd", true},
		{"backslash dotdot", "..\\etc\\passwd", true},
		{"dotdot only", "..", true},
		{"dotdot slash", "../", true},
		{"clean dotdot", "a/b/../../../etc/passwd", true},
		// Valid entries
		{"normal file", "src/main.go", false},
		{"nested valid", "a/b/c/d.go", false},
		{"dot prefix", "./src/main.go", false}, // trimmed to src/main.go
		{"empty", "", false},                   // returns "", nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cleanZipEntryName(tt.entry)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %q, got result=%q", tt.entry, result)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.entry, err)
			}
		})
	}
}

func TestStageZip_PathTraversal(t *testing.T) {
	// Create a malicious zip file with path traversal entries
	zipPath := filepath.Join(t.TempDir(), "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	// Add a normal file
	fw, err := w.Create("normal.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("normal content"))

	// Add a traversal file - this uses the raw header to set the name
	header := &zip.FileHeader{
		Name:   "../../../tmp/evil.txt",
		Method: zip.Deflate,
	}
	fw2, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	fw2.Write([]byte("evil content"))

	w.Close()
	f.Close()

	// Staging should fail or skip the traversal entry
	out := t.TempDir()
	_, err = Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err == nil {
		// If it didn't error, verify no files escaped
		evilPath := filepath.Join(out, "..", "..", "..", "tmp", "evil.txt")
		if _, statErr := os.Stat(evilPath); statErr == nil {
			t.Fatal("ZIP PATH TRAVERSAL: evil file was written outside workspace")
		}
	}
	// Error is the expected safe behavior
}

func TestStageZip_SymlinkEntry(t *testing.T) {
	// Create a zip with a symlink entry
	zipPath := filepath.Join(t.TempDir(), "symlink.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	// Normal file
	fw, err := w.Create("normal.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("normal content"))

	// Symlink entry
	header := &zip.FileHeader{
		Name: "link.txt",
	}
	header.SetMode(os.ModeSymlink | 0o777)
	fw2, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	fw2.Write([]byte("/etc/passwd"))

	w.Close()
	f.Close()

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage failed: %v", err)
	}

	// Symlink entry should be skipped
	if res.Manifest.SkippedByReason["symlink"] < 1 {
		t.Error("expected symlink entry to be skipped")
	}
}

func TestStageZip_ZeroByteBudget(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	fw, _ := w.Create("file.txt")
	fw.Write([]byte("content"))
	w.Close()
	f.Close()

	_, err = Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    t.TempDir(),
		MaxFiles:  100,
		MaxBytes:  0,
	})
	if err == nil {
		t.Error("expected error for zero byte budget")
	}
}

func TestStageZip_ManyEntries(t *testing.T) {
	// Test with entry count exceeding limit
	zipPath := filepath.Join(t.TempDir(), "many.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	// Create more entries than maxFiles * zipEntryLimitMultiplier allows
	for i := 0; i < 100; i++ {
		fw, _ := w.Create("file" + string(rune('a'+i%26)) + ".txt")
		fw.Write([]byte("content"))
	}
	w.Close()
	f.Close()

	_, err = Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    t.TempDir(),
		MaxFiles:  2, // Very low limit
		MaxBytes:  1024 * 1024,
	})
	if err == nil {
		t.Error("expected error for too many zip entries")
	}
}

func TestStageZip_EmptyZip(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "empty.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	w.Close()
	f.Close()

	out := t.TempDir()
	res, err := Stage(StageOptions{
		InputPath: zipPath,
		OutDir:    out,
		MaxFiles:  100,
		MaxBytes:  1024 * 1024,
	})
	if err != nil {
		t.Fatalf("stage of empty zip should succeed: %v", err)
	}
	if res.Manifest.IncludedFiles != 0 {
		t.Errorf("expected 0 files from empty zip, got %d", res.Manifest.IncludedFiles)
	}
}
