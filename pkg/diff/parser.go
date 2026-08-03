// Package diff parses unified diffs and reports which lines were added,
// per file, in the new version of the content. RouteWarden uses this to
// scope AST analysis to only the lines a PR actually changed (rule R5).
package diff

import (
	"fmt"
	"io"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
)

// AddedLines maps a file's new path (post-change) to the sorted list of
// 1-indexed line numbers that were added by the diff.
type AddedLines map[string][]int

// ParseAddedLines parses a unified diff (as produced by `git diff` or the
// GitHub Compare/Pull Request diff endpoints) and returns, per file, the
// line numbers that were added in the new version of the file.
//
// Deleted files are skipped entirely: there is no "new" content to scan.
// Renamed-without-modification files with no text fragments simply produce
// no entries, since there is nothing new to report.
func ParseAddedLines(r io.Reader) (AddedLines, error) {
	files, _, err := gitdiff.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("diff: parse patch: %w", err)
	}

	result := make(AddedLines)

	for _, f := range files {
		if f.IsDelete || f.IsBinary {
			continue
		}

		path := f.NewName
		if path == "" {
			path = f.OldName
		}

		var added []int
		for _, frag := range f.TextFragments {
			newLine := frag.NewPosition
			for _, line := range frag.Lines {
				switch line.Op {
				case gitdiff.OpAdd:
					added = append(added, int(newLine))
					newLine++
				case gitdiff.OpContext:
					newLine++
				case gitdiff.OpDelete:
					// Deleted lines only existed in the old file; they do
					// not consume a line number in the new file.
				}
			}
		}

		if len(added) > 0 {
			result[path] = added
		}
	}

	return result, nil
}
