package migrate

import (
	"context"
	"io/fs"
	"regexp"
	"strconv"
	"testing/fstest"
)

var versionOf = regexp.MustCompile(`^([0-9]{5})_`)

// RunUpTo applies the embedded migrations whose version is at most max, the state of a deployment that has
// not been upgraded yet. A test then inserts rows the way that release wrote them and runs Run.
func RunUpTo(ctx context.Context, databaseURL string, max int) ([]string, error) {
	all, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	files, err := fs.ReadDir(all, ".")
	if err != nil {
		return nil, err
	}
	kept := fstest.MapFS{}
	for _, f := range files {
		match := versionOf.FindStringSubmatch(f.Name())
		if match == nil {
			continue
		}
		if version, _ := strconv.Atoi(match[1]); version > max {
			continue
		}
		data, err := fs.ReadFile(all, f.Name())
		if err != nil {
			return nil, err
		}
		kept[f.Name()] = &fstest.MapFile{Data: data}
	}
	return run(ctx, databaseURL, kept)
}
