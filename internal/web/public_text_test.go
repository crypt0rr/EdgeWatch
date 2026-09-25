package web

import (
	"strings"
	"testing"
)

func TestPublicDashboardTextErrorNamesOnlyTheFailingField(t *testing.T) {
	for _, tc := range []struct {
		name         string
		title        string
		introduction string
		message      string
		details      map[string]string
	}{
		{name: "valid", title: "Edge status", introduction: "Monitored services"},
		{name: "valid at the limits", title: strings.Repeat("é", 120), introduction: strings.Repeat("🙂", 500)},
		{
			name: "introduction line break", title: "Edge status", introduction: "Line one\nLine two",
			message: "the public status introduction cannot contain line breaks",
			details: map[string]string{"introduction": "the public status introduction cannot contain line breaks"},
		},
		{
			name: "introduction carriage return", introduction: "Line one\rLine two",
			message: "the public status introduction cannot contain line breaks",
			details: map[string]string{"introduction": "the public status introduction cannot contain line breaks"},
		},
		{
			name: "long title", title: strings.Repeat("x", 121),
			message: "the public status title must be at most 120 characters",
			details: map[string]string{"title": "the public status title must be at most 120 characters"},
		},
		{
			name: "both fields", title: "Edge\nstatus", introduction: strings.Repeat("x", 501) + "\n",
			message: "the public status title cannot contain line breaks; the public status introduction must be at most 500 characters and cannot contain line breaks",
			details: map[string]string{
				"title":        "the public status title cannot contain line breaks",
				"introduction": "the public status introduction must be at most 500 characters and cannot contain line breaks",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, details := publicDashboardTextError(tc.title, tc.introduction)
			if message != tc.message {
				t.Fatalf("message = %q, want %q", message, tc.message)
			}
			if len(details) != len(tc.details) {
				t.Fatalf("details = %#v, want %#v", details, tc.details)
			}
			for field, want := range tc.details {
				if details[field] != want {
					t.Fatalf("details[%s] = %q, want %q", field, details[field], want)
				}
			}
		})
	}
}
