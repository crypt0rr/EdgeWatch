package web

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/apitypes"
)

// Every exported field of the response structs that the console's
// generated types come from has a json tag, and every struct that they
// contain is listed too, so the declarations can be generated.
func TestResponseTypesHaveJSONTags(t *testing.T) {
	t.Parallel()
	if err := apitypes.CheckTags(ResponseTypes()); err != nil {
		t.Fatal(err)
	}
	if _, err := apitypes.Generate(ResponseTypes()); err != nil {
		t.Fatal(err)
	}
}
