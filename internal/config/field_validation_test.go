package config

import (
	"errors"
	"testing"
)

func TestFieldValidationErrorPreservesMessageAndField(t *testing.T) {
	if got := NewFieldValidationError("schedule", nil); got != nil {
		t.Fatalf("nil validation error = %v, want nil", got)
	}

	want := errors.New("invalid schedule")
	wrapped := NewFieldValidationError("schedule", want)
	if wrapped.Error() != want.Error() {
		t.Fatalf("validation message = %q, want unchanged %q", wrapped.Error(), want.Error())
	}
	if !errors.Is(wrapped, want) {
		t.Fatalf("field validation error %v does not unwrap to its cause", wrapped)
	}
	var fieldError *FieldValidationError
	if !errors.As(wrapped, &fieldError) || fieldError.Field != "schedule" {
		t.Fatalf("field validation error = %#v, want field schedule", fieldError)
	}
}
