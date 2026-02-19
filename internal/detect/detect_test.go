package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProject(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, root string)
		wantType  string
		wantLabel string
	}{
		{
			name: "nextjs project via next.config.js",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "next.config.js"), "module.exports = {}")
				writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"next":"14.0.0"}}`)
			},
			wantType:  "nextjs",
			wantLabel: "Next.js",
		},
		{
			name: "nextjs project via next.config.mjs",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "next.config.mjs"), "export default {}")
			},
			wantType:  "nextjs",
			wantLabel: "Next.js",
		},
		{
			name: "nextjs project via next.config.ts",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "next.config.ts"), "export default {}")
			},
			wantType:  "nextjs",
			wantLabel: "Next.js",
		},
		{
			name: "supabase project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				mkDir(t, filepath.Join(root, "supabase"))
				writeFile(t, filepath.Join(root, "supabase", "config.toml"), "[project]\nid = \"abc\"")
			},
			wantType:  "supabase",
			wantLabel: "Supabase",
		},
		{
			name: "express project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "package.json"), `{
					"dependencies": {
						"express": "^4.18.0"
					}
				}`)
			},
			wantType:  "express",
			wantLabel: "Express",
		},
		{
			name: "fastify project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "package.json"), `{
					"dependencies": {
						"fastify": "^4.0.0"
					}
				}`)
			},
			wantType:  "fastify",
			wantLabel: "Fastify",
		},
		{
			name: "fastapi project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "uvicorn==0.20.0\nfastapi==0.100.0\npydantic==2.0")
			},
			wantType:  "fastapi",
			wantLabel: "FastAPI",
		},
		{
			name: "flask project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "flask==3.0.0\njinja2==3.1.0")
			},
			wantType:  "flask",
			wantLabel: "Flask",
		},
		{
			name: "django project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "django==5.0\ncelery==5.3")
			},
			wantType:  "django",
			wantLabel: "Django",
		},
		{
			name: "go project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22")
			},
			wantType:  "go",
			wantLabel: "Go",
		},
		{
			name: "rust project",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname = \"app\"")
			},
			wantType:  "rust",
			wantLabel: "Rust",
		},
		{
			name: "node fallback with package.json only",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "package.json"), `{
					"dependencies": {
						"lodash": "^4.17.0",
						"axios": "^1.0.0"
					}
				}`)
			},
			wantType:  "node",
			wantLabel: "Node.js",
		},
		{
			name: "python fallback via requirements.txt",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "requests==2.31.0\nbeautifulsoup4==4.12")
			},
			wantType:  "python",
			wantLabel: "Python",
		},
		{
			name: "python fallback via pyproject.toml",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "pyproject.toml"), "[project]\nname = \"myapp\"")
			},
			wantType:  "python",
			wantLabel: "Python",
		},
		{
			name: "python fallback via setup.py",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "setup.py"), "from setuptools import setup\nsetup()")
			},
			wantType:  "python",
			wantLabel: "Python",
		},
		{
			name: "unknown empty directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				// leave dir empty
			},
			wantType:  "",
			wantLabel: "",
		},
		{
			name: "express in devDependencies",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "package.json"), `{
					"devDependencies": {
						"express": "^4.18.0"
					}
				}`)
			},
			wantType:  "express",
			wantLabel: "Express",
		},
		{
			name: "nextjs takes priority over express in package.json",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "next.config.js"), "module.exports = {}")
				writeFile(t, filepath.Join(root, "package.json"), `{
					"dependencies": {
						"express": "^4.18.0",
						"next": "^14.0.0"
					}
				}`)
			},
			wantType:  "nextjs",
			wantLabel: "Next.js",
		},
		{
			name: "fastapi with comment lines in requirements.txt",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "# dependencies\nfastapi>=0.100\n# end")
			},
			wantType:  "fastapi",
			wantLabel: "FastAPI",
		},
		{
			name: "fastapi priority over django",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeFile(t, filepath.Join(root, "requirements.txt"), "fastapi==0.100.0\ndjango==5.0")
			},
			wantType:  "fastapi",
			wantLabel: "FastAPI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setup(t, root)

			got := Project(root)

			if got.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", got.Label, tt.wantLabel)
			}
		})
	}
}

// writeFile creates a file (and parent dirs) with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mkDir creates a directory (and parents).
func mkDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
