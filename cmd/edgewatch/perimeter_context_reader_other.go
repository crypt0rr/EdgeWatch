//go:build !unix

package main

import (
	"context"
	"io"
)

func perimeterInputWithCancellation(ctx context.Context, input io.Reader) (io.Reader, func() bool) {
	if closer, ok := input.(io.Closer); ok {
		return input, context.AfterFunc(ctx, func() { _ = closer.Close() })
	}
	return input, nil
}
