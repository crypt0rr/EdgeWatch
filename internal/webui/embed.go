package webui

import (
	"embed"
	"io/fs"
)

// Dist is populated by the frontend build. The checked-in marker keeps the Go
// package buildable before Node dependencies have been installed locally.
//
//go:embed all:dist
var Dist embed.FS

func Files() fs.FS { return Dist }
