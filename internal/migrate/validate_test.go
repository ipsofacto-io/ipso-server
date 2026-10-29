package migrate

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

const goodUp = "-- +goose Up\nCREATE TABLE t (id int);\n"

func files(entries map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, body := range entries {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func TestValidateAcceptsTheEmbeddedMigrations(t *testing.T) {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fsys); err != nil {
		t.Fatalf("the embedded migrations must pass: %v", err)
	}
}

func TestValidateAcceptsAllowedAnnotations(t *testing.T) {
	body := "-- +goose NO TRANSACTION\n-- +goose Up\n-- +goose StatementBegin\nSELECT 1;\n-- +goose StatementEnd\n"
	if err := Validate(files(map[string]string{"00001_a.sql": body})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]string
		want    string
	}{
		{
			name:    "down section",
			entries: map[string]string{"00001_a.sql": goodUp + "-- +goose Down\nDROP TABLE t;\n"},
			want:    `annotation "Down" is not allowed`,
		},
		{
			name:    "down section in another case",
			entries: map[string]string{"00001_a.sql": goodUp + "--+goose DOWN\nDROP TABLE t;\n"},
			want:    `annotation "Down" is not allowed`,
		},
		{
			name:    "envsub on",
			entries: map[string]string{"00001_a.sql": "-- +goose Up\n-- +goose ENVSUB ON\nSELECT '${X}';\n"},
			want:    `annotation "ENVSUB ON" is not allowed`,
		},
		{
			name:    "envsub off in lower case",
			entries: map[string]string{"00001_a.sql": "-- +goose Up\n-- +goose envsub off\nSELECT 1;\n"},
			want:    `annotation "ENVSUB OFF" is not allowed`,
		},
		{
			name:    "annotation inside a function body",
			entries: map[string]string{"00001_a.sql": "-- +goose Up\n-- +goose StatementBegin\nCREATE FUNCTION f() RETURNS int AS $$\n-- +goose Down\nSELECT 1\n$$ LANGUAGE sql;\n-- +goose StatementEnd\n"},
			want:    `annotation "Down" is not allowed`,
		},
		{
			name:    "unknown annotation",
			entries: map[string]string{"00001_a.sql": goodUp + "-- +goose Sideways\n"},
			want:    `unknown goose annotation "Sideways"`,
		},
		{
			name:    "indented annotation",
			entries: map[string]string{"00001_a.sql": goodUp + "  -- +goose StatementBegin\n"},
			want:    "leading whitespace",
		},
		{
			name:    "two annotations on one line",
			entries: map[string]string{"00001_a.sql": goodUp + "-- +goose Up +goose Down\n"},
			want:    "more than one '+goose'",
		},
		{
			name:    "missing up",
			entries: map[string]string{"00001_a.sql": "CREATE TABLE t (id int);\n"},
			want:    "exactly one '-- +goose Up', found 0",
		},
		{
			name:    "two ups",
			entries: map[string]string{"00001_a.sql": goodUp + "-- +goose Up\n"},
			want:    "exactly one '-- +goose Up', found 2",
		},
		{
			name:    "duplicate version",
			entries: map[string]string{"00001_a.sql": goodUp, "00001_b.sql": goodUp},
			want:    "duplicate version 1",
		},
		{
			name:    "version gap",
			entries: map[string]string{"00001_a.sql": goodUp, "00003_c.sql": goodUp},
			want:    "version 3 breaks the sequence, want 2",
		},
		{
			name:    "sequence does not start at one",
			entries: map[string]string{"00002_b.sql": goodUp},
			want:    "version 2 breaks the sequence, want 1",
		},
		{
			name:    "file that is not sql",
			entries: map[string]string{"00001_a.sql": goodUp, "README.md": "# notes\n"},
			want:    "README.md: not a migration file name",
		},
		{
			name:    "backup copy of a migration",
			entries: map[string]string{"00001_a.sql": goodUp, "00001_a.sql.bak": goodUp},
			want:    "00001_a.sql.bak: not a migration file name",
		},
		{
			name:    "hidden file",
			entries: map[string]string{"00001_a.sql": goodUp, ".gitkeep": ""},
			want:    ".gitkeep: not a migration file name",
		},
		{
			name:    "go source",
			entries: map[string]string{"00001_a.sql": goodUp, "00002_b.go": "package migrations\n"},
			want:    "00002_b.go: not a migration file name",
		},
		{
			name:    "version with the wrong width",
			entries: map[string]string{"1_a.sql": goodUp},
			want:    "1_a.sql: not a migration file name",
		},
		{
			name:    "upper case slug",
			entries: map[string]string{"00001_Add.sql": goodUp},
			want:    "00001_Add.sql: not a migration file name",
		},
		{
			name:    "no migrations",
			entries: map[string]string{},
			want:    "no migrations",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(files(tt.entries))
			if err == nil {
				t.Fatalf("want an error containing %q, got none", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want an error containing %q, got %q", tt.want, err)
			}
		})
	}
}

func TestValidateRejectsADirectory(t *testing.T) {
	fsys := files(map[string]string{"00001_a.sql": goodUp, "sub/00002_b.sql": goodUp})
	err := Validate(fsys)
	if err == nil || !strings.Contains(err.Error(), "sub: not a regular file") {
		t.Fatalf("want a directory error, got %v", err)
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	err := Validate(files(map[string]string{
		"00001_a.sql": goodUp + "-- +goose Down\n",
		"notes.txt":   "",
	}))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{`annotation "Down" is not allowed`, "notes.txt: not a migration file name"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
