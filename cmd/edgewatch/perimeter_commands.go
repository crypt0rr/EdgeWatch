package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const maxPerimeterInputLineBytes = 64 * 1024

// listPerimeter prints the selected unit's declared ranges. The store returns
// them in address order and scopes the query to the tenant store.
func listPerimeter(ctx context.Context, tenant *store.TenantStore, output string) error {
	seeds, err := tenant.ListPerimeterSeeds(ctx)
	if err != nil {
		return err
	}
	if output == "json" {
		return printValue(output, seeds)
	}
	if len(seeds) == 0 {
		return printValue(output, "No declared perimeter ranges.")
	}
	lines := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		line := seed.Kind + " " + seed.Value
		if seed.Label != "" {
			line += " " + seed.Label
		}
		lines = append(lines, line)
	}
	return printValue(output, strings.Join(lines, "\n"))
}

// declarePerimeter reads one file or standard input completely before it
// calls the store's transaction. The store commits ranges and the host audit
// record together, and rejects a declaration with any refused entry.
func declarePerimeter(ctx context.Context, tenant *store.TenantStore, kind, from string, stdin io.Reader, output string) error {
	input := stdin
	if from != "-" {
		file, err := os.Open(from)
		if err != nil {
			// Do not include an operator-supplied path in an error or log.
			return errors.New("could not open perimeter declaration input")
		}
		defer file.Close()
		input = file
	}
	entries, lineNumbers, err := parsePerimeterDeclarationContext(ctx, input, kind)
	if err != nil {
		return err
	}
	result, err := tenant.DeclarePerimeterSeeds(ctx, entries, store.AuditEntry{
		ActorUsername: hostCLIActor,
		ActorKind:     store.AuditActorHost,
	})
	if err != nil {
		return perimeterDeclarationError(err, lineNumbers)
	}
	if output == "json" {
		return printValue(output, result)
	}
	return printValue(output, perimeterDeclareSummary(result))
}

// parsePerimeterDeclarationContext closes a closeable input when ctx is
// canceled, interrupting a Scanner blocked in Read. In particular, this
// lets command cancellation stop a read from stdin without waiting for its
// writer to close.
func parsePerimeterDeclarationContext(ctx context.Context, input io.Reader, kind string) ([]store.PerimeterEntry, []int, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var stopClosingInput func() bool
	if closer, ok := input.(io.Closer); ok {
		stopClosingInput = context.AfterFunc(ctx, func() { _ = closer.Close() })
	}
	entries, lineNumbers, err := parsePerimeterDeclaration(input, kind)
	if stopClosingInput != nil {
		stopClosingInput()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, nil, ctxErr
	}
	return entries, lineNumbers, err
}

// parsePerimeterDeclaration matches the Perimeter form's line format: one IP
// address or CIDR prefix, then an optional label. Blank lines are ignored.
// It retains source line numbers for bounded, value-free refusal messages.
func parsePerimeterDeclaration(input io.Reader, kind string) ([]store.PerimeterEntry, []int, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxPerimeterInputLineBytes)
	scanner.Split(splitPerimeterLines)
	entries := make([]store.PerimeterEntry, 0, store.MaxPerimeterEntriesPerRequest)
	lineNumbers := make([]int, 0, store.MaxPerimeterEntriesPerRequest)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(entries) == store.MaxPerimeterEntriesPerRequest {
			return nil, nil, fmt.Errorf("declare between 1 and %d entries", store.MaxPerimeterEntriesPerRequest)
		}
		value := line
		label := ""
		if split := strings.IndexFunc(line, unicode.IsSpace); split >= 0 {
			value = line[:split]
			label = strings.TrimSpace(line[split:])
		}
		entries = append(entries, store.PerimeterEntry{Kind: kind, Value: value, Label: label})
		lineNumbers = append(lineNumbers, lineNumber)
	}
	if scanner.Err() != nil {
		// Scanner errors can be caused by a line beyond the parser bound. Keep
		// the input itself, including labels, out of command output.
		return nil, nil, errors.New("could not read perimeter declaration input")
	}
	return entries, lineNumbers, nil
}

// splitPerimeterLines recognizes Unix, Windows, and legacy Mac line endings,
// matching the line splitting used by the Perimeter form.
func splitPerimeterLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for index, value := range data {
		switch value {
		case '\n':
			return index + 1, data[:index], nil
		case '\r':
			if index+1 == len(data) && !atEOF {
				return 0, nil, nil
			}
			if index+1 < len(data) && data[index+1] == '\n' {
				return index + 2, data[:index], nil
			}
			return index + 1, data[:index], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// perimeterDeclarationError maps entry indexes back to source lines while
// leaving submitted addresses, labels, and file paths out of stderr.
func perimeterDeclarationError(err error, lineNumbers []int) error {
	var refused *store.PerimeterValidationError
	if !errors.As(err, &refused) {
		return err
	}
	lines := make([]string, 0, len(refused.Entries))
	for _, entry := range refused.Entries {
		line := entry.Index + 1
		if entry.Index >= 0 && entry.Index < len(lineNumbers) {
			line = lineNumbers[entry.Index]
		}
		lines = append(lines, fmt.Sprintf("line %d: %s", line, entry.Reason))
	}
	return fmt.Errorf("%w; %s", err, strings.Join(lines, "; "))
}

func perimeterDeclareSummary(result store.PerimeterDeclareResult) string {
	createdNoun := "new ranges"
	if result.Created == 1 {
		createdNoun = "new range"
	}
	skippedNoun := "already-declared entries were"
	if result.Skipped == 1 {
		skippedNoun = "already-declared entry was"
	}
	if result.Created == 0 {
		return fmt.Sprintf("No new ranges were declared; %d %s skipped.", result.Skipped, skippedNoun)
	}
	if result.Skipped == 0 {
		return fmt.Sprintf("Declared %d %s.", result.Created, createdNoun)
	}
	return fmt.Sprintf("Declared %d %s; %d %s skipped.", result.Created, createdNoun, result.Skipped, skippedNoun)
}
