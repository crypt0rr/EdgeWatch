package webui

import (
	"io"
	"strings"
	"testing"
)

func TestFilesExposeEmbeddedFrontendContract(t *testing.T) {
	fsys := Files()

	index, err := fsys.Open("dist/index.html")
	if err != nil {
		// The repository intentionally keeps only .gitkeep in the generated
		// directory so Go-only workflows remain buildable before Node is
		// installed. CI builds the frontend before running this contract test;
		// a clean Go checkout should skip rather than report a false failure.
		marker, markerErr := fsys.Open("dist/.gitkeep")
		if markerErr != nil {
			t.Fatalf("open embedded index: %v", err)
		}
		_ = marker.Close()
		t.Skip("embedded frontend assets are not built; run npm run build first")
	}
	defer index.Close()

	data, err := io.ReadAll(io.LimitReader(index, 2<<20))
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	markup := string(data)
	for _, fragment := range []string{"<div id=\"root\">", "EdgeWatch", "/favicon.svg"} {
		if !strings.Contains(markup, fragment) {
			t.Errorf("embedded index is missing %q", fragment)
		}
	}

	icon, err := fsys.Open("dist/favicon.svg")
	if err != nil {
		t.Fatalf("open embedded favicon: %v", err)
	}
	defer icon.Close()
	iconData, err := io.ReadAll(io.LimitReader(icon, 64))
	if err != nil || len(iconData) == 0 {
		t.Fatalf("embedded favicon is empty: bytes=%d err=%v", len(iconData), err)
	}
}
