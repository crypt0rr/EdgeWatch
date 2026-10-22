package main

import (
	"context"
	"io"
	"os"
)

// perimeterFileInputWithCancellation is replaced by the Unix implementation
// during package initialization. Other platforms use Close-on-cancel for
// file-backed input, as they do for other closable readers.
var perimeterFileInputWithCancellation = perimeterDefaultFileInputWithCancellation

// perimeterInputWithCancellation makes file-backed input cancellation-aware
// without relying on Close to interrupt a blocked operating-system read.
func perimeterInputWithCancellation(ctx context.Context, input io.Reader) (io.Reader, func() bool) {
	if file, ok := input.(*os.File); ok {
		return perimeterFileInputWithCancellation(ctx, file)
	}
	return perimeterCloseInputOnCancellation(ctx, input)
}

func perimeterDefaultFileInputWithCancellation(ctx context.Context, file *os.File) (io.Reader, func() bool) {
	return perimeterCloseInputOnCancellation(ctx, file)
}

func perimeterCloseInputOnCancellation(ctx context.Context, input io.Reader) (io.Reader, func() bool) {
	if closer, ok := input.(io.Closer); ok {
		return input, context.AfterFunc(ctx, func() { _ = closer.Close() })
	}
	return input, nil
}
