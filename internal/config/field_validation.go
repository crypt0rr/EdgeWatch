package config

// FieldValidationError associates a caller-correctable validation failure
// with the stable API field that should display it. Field names are metadata
// and are deliberately not added to Error(), preserving existing messages.
type FieldValidationError struct {
	Field string
	Err   error
}

func (e *FieldValidationError) Error() string { return e.Err.Error() }

func (e *FieldValidationError) Unwrap() error { return e.Err }

// NewFieldValidationError wraps err with the field that owns the failure. A
// nil error remains nil so validators can tag their return values directly.
func NewFieldValidationError(field string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldValidationError{Field: field, Err: err}
}
