// Package ui writes the human-facing side of the CLI — the banner, the
// progress bars, the scan summary and warnings — to stderr.
//
// stdout is reserved for the answer the caller asked for: the findings report,
// the shell completion script, the rules listing. Keeping the two apart is what
// makes `drogonsec scan . --format json > report.json` produce a valid file
// while the banner still appears on the terminal, and it is what lets an editor
// extension read the scanner's output at all.
//
// Nothing is hidden by this: stderr goes to the terminal by default, so an
// interactive run looks exactly as it did before.
package ui

import (
	"fmt"
	"io"
	"os"
)

// Out is where human-facing output goes. It is a variable so tests can capture
// it.
var Out io.Writer = os.Stderr

// A note on colour, since it is not obvious and the tempting change is wrong.
//
// fatih/color decides whether to emit ANSI escapes by looking at stdout, and it
// stays that way deliberately. Binding the decision to stderr instead would
// keep the banner colourful when stdout is redirected — but it would also put
// escape codes inside a redirected text report, because the report is written
// to stdout by the same library calls. Corrupting the data to keep the
// decoration pretty is the wrong trade, so the cost is accepted the other way
// round: `drogonsec scan . > report.txt` writes a clean report and draws a
// colourless banner.
//
// Getting both right needs a per-stream colour context rather than the
// library's single global, which is a larger change than it is worth today.

// Printf writes formatted human-facing output.
func Printf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(Out, format, a...)
}

// Println writes a line of human-facing output.
func Println(a ...interface{}) {
	_, _ = fmt.Fprintln(Out, a...)
}

// Print writes human-facing output.
func Print(a ...interface{}) {
	_, _ = fmt.Fprint(Out, a...)
}
