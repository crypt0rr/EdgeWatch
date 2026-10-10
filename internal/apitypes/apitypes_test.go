package apitypes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureInner struct {
	Name string `json:"name"`
}

type fixtureEmpty struct{}

type fixtureEverything struct {
	Text        string           `json:"text"`
	Flag        bool             `json:"flag"`
	Count       int              `json:"count"`
	Small       int8             `json:"small"`
	Unsigned    uint64           `json:"unsigned"`
	Ratio       float64          `json:"ratio"`
	At          time.Time        `json:"at"`
	AtMaybe     time.Time        `json:"at_maybe,omitzero"`
	AtPointer   *time.Time       `json:"at_pointer"`
	Optional    string           `json:"optional,omitempty"`
	Pointer     *int             `json:"pointer"`
	PointerOmit *int             `json:"pointer_omit,omitempty"`
	Double      **string         `json:"double"`
	List        []string         `json:"list"`
	ListOmit    []string         `json:"list_omit,omitempty"`
	Pointers    []*fixtureInner  `json:"pointers,omitempty"`
	Bytes       []byte           `json:"bytes"`
	Fixed       [2]int           `json:"fixed,omitempty"`
	NoElements  [0]int           `json:"no_elements,omitempty"`
	Lookup      map[string]int   `json:"lookup"`
	Numbered    map[int][]string `json:"numbered,omitempty"`
	Anything    any              `json:"anything"`
	AnythingOpt any              `json:"anything_opt,omitempty"`
	Inner       fixtureInner     `json:"inner,omitempty"`
	InnerZero   fixtureInner     `json:"inner_zero,omitzero"`
	Inline      struct {
		A int     `json:"a"`
		B *string `json:"b,omitempty"`
	} `json:"inline"`
	Nothing    struct{}     `json:"nothing"`
	Empty      fixtureEmpty `json:"empty"`
	Dashed     string       `json:"dashed-name"`
	Skipped    string       `json:"-"`
	unexported string
	Unlisted   func() `json:"-"`
}

func TestGenerateDeclaresTheJSONThatEncodingJSONWrites(t *testing.T) {
	t.Parallel()
	got, err := Generate([]Type{{Name: "Everything", Value: fixtureEverything{unexported: "unused"}}, {Name: "Inner", Value: fixtureInner{}}, {Name: "Empty", Value: fixtureEmpty{}}})
	if err != nil {
		t.Fatal(err)
	}
	want := Header + `

// Everything is apitypes.fixtureEverything.
export type Everything = {
  text: string
  flag: boolean
  count: number
  small: number
  unsigned: number
  ratio: number
  at: string
  at_maybe?: string
  at_pointer: string | null
  optional?: string
  pointer: number | null
  pointer_omit?: number
  double: string | null
  list: string[] | null
  list_omit?: string[]
  pointers?: (Inner | null)[]
  bytes: string | null
  fixed: number[]
  no_elements?: number[]
  lookup: Record<string, number> | null
  numbered?: Record<string, string[] | null>
  anything: unknown
  anything_opt?: unknown
  inner: Inner
  inner_zero?: Inner
  inline: { a: number; b?: string }
  nothing: Record<string, never>
  empty: Empty
  "dashed-name": string
}

// Inner is apitypes.fixtureInner.
export type Inner = {
  name: string
}

// Empty is apitypes.fixtureEmpty.
export type Empty = Record<string, never>
`
	if string(got) != want {
		t.Fatalf("Generate =\n%s\nwant\n%s", got, want)
	}
}

// The optional properties are the fields that encoding/json leaves out of a
// zero value, and the properties that admit null are the ones that it writes
// as null there.
func TestGeneratedPropertiesMatchTheZeroValuesJSON(t *testing.T) {
	t.Parallel()
	generated, err := Generate([]Type{{Name: "Everything", Value: fixtureEverything{}}, {Name: "Inner", Value: fixtureInner{}}, {Name: "Empty", Value: fixtureEmpty{}}})
	if err != nil {
		t.Fatal(err)
	}
	_, declaration, _ := strings.Cut(string(generated), "export type Everything = {\n")
	declaration, _, _ = strings.Cut(declaration, "\n}\n")
	raw, err := json.Marshal(fixtureEverything{})
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatal(err)
	}
	required := 0
	for line := range strings.SplitSeq(declaration, "\n") {
		property, value, _ := strings.Cut(strings.TrimSpace(line), ": ")
		optional := strings.HasSuffix(property, "?")
		name := strings.Trim(strings.TrimSuffix(property, "?"), `"`)
		written, present := encoded[name]
		if optional == present {
			t.Errorf("%s is optional %t, but the zero value's JSON has it %t", name, optional, present)
			continue
		}
		if !present {
			continue
		}
		required++
		if null := string(written) == "null"; null != (strings.HasSuffix(value, " | null") || value == "unknown") {
			t.Errorf("%s is %s, but the zero value's JSON writes %s", name, value, written)
		}
	}
	if required != len(encoded) {
		t.Errorf("the declaration requires %d properties, the zero value's JSON has %d: %s", required, len(encoded), raw)
	}
}

type fixtureUntagged struct {
	Tagged   string `json:"tagged"`
	Untagged string
	Nameless string `json:",omitempty"`
	Nested   []struct {
		Inner string
	} `json:"nested"`
	hidden string
}

type fixtureEmbedded struct {
	fixtureInner
	Other string `json:"other"`
}

type fixtureStringOption struct {
	Count int `json:"count,string"`
}

type fixtureUnregistered struct {
	Inner fixtureInner `json:"inner"`
}

type fixtureJSONMarshaler struct{}

func (fixtureJSONMarshaler) MarshalJSON() ([]byte, error) { return []byte(`1`), nil }

type fixtureTextMarshaler struct{}

func (*fixtureTextMarshaler) MarshalText() ([]byte, error) { return []byte(`text`), nil }

type fixtureMarshalers struct {
	JSON fixtureJSONMarshaler `json:"json"`
}

type fixtureTextMarshalers struct {
	Text []fixtureTextMarshaler `json:"text"`
}

type fixtureStructKey struct {
	Lookup map[fixtureInner]string `json:"lookup"`
}

type fixtureChannel struct {
	Channel chan int `json:"channel"`
}

type fixtureComplexElements struct {
	Values map[string][]complex64 `json:"values"`
}

type fixtureBadPointer struct {
	Values *[1]chan int `json:"values"`
}

type fixtureBadArray struct {
	Values [1]func() `json:"values"`
}

type fixtureBadInline struct {
	Inline struct {
		Untagged string
	} `json:"inline"`
}

func TestGenerateRefusesWhatItCannotDescribe(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		types []Type
		want  string
	}{
		{"nil value", []Type{{Name: "Nil"}}, "Nil: <nil> is not a named struct"},
		{"not a struct", []Type{{Name: "Number", Value: 1}}, "Number: int is not a named struct"},
		{"anonymous struct", []Type{{Name: "Anonymous", Value: struct{}{}}}, "is not a named struct"},
		{"invalid name", []Type{{Name: "not-a-name", Value: fixtureInner{}}}, `"not-a-name" is not a TypeScript name`},
		{"name twice", []Type{{Name: "Inner", Value: fixtureInner{}}, {Name: "Inner", Value: fixtureEmpty{}}}, "the name Inner is registered twice"},
		{"struct twice", []Type{{Name: "Inner", Value: fixtureInner{}}, {Name: "Again", Value: fixtureInner{}}}, "registered as Inner and Again"},
		{"untagged field", []Type{{Name: "Untagged", Value: fixtureUntagged{}}}, "fixtureUntagged.Untagged: has no json tag"},
		{"embedded field", []Type{{Name: "Embedded", Value: fixtureEmbedded{}}, {Name: "Inner", Value: fixtureInner{}}}, "fixtureEmbedded.fixtureInner: embedded fields are not supported"},
		{"string option", []Type{{Name: "Option", Value: fixtureStringOption{}}}, "the string option is not supported"},
		{"unregistered struct", []Type{{Name: "Unregistered", Value: fixtureUnregistered{}}}, "apitypes.fixtureInner is not registered"},
		{"MarshalJSON", []Type{{Name: "Marshalers", Value: fixtureMarshalers{}}}, "fixtureJSONMarshaler encodes itself"},
		{"MarshalText", []Type{{Name: "Marshalers", Value: fixtureTextMarshalers{}}}, "fixtureTextMarshaler encodes itself"},
		{"struct key", []Type{{Name: "Keys", Value: fixtureStructKey{}}, {Name: "Inner", Value: fixtureInner{}}}, "map key apitypes.fixtureInner is not supported"},
		{"channel", []Type{{Name: "Channel", Value: fixtureChannel{}}}, "chan int cannot be encoded as JSON"},
		{"map elements", []Type{{Name: "Complex", Value: fixtureComplexElements{}}}, "complex64 cannot be encoded as JSON"},
		{"pointer elements", []Type{{Name: "Pointer", Value: fixtureBadPointer{}}}, "chan int cannot be encoded as JSON"},
		{"array elements", []Type{{Name: "Array", Value: fixtureBadArray{}}}, "func() cannot be encoded as JSON"},
		{"inline struct", []Type{{Name: "Inline", Value: fixtureBadInline{}}}, ".Untagged: has no json tag"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Generate(test.types); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Generate error = %v, want one containing %q", err, test.want)
			}
		})
	}
}

// go vet refuses a struct type that declares a JSON name twice, so the
// struct is built at run time.
func TestGenerateRefusesAJSONNameDeclaredTwice(t *testing.T) {
	t.Parallel()
	text := reflect.TypeFor[string]()
	duplicate := reflect.StructOf([]reflect.StructField{
		{Name: "First", Type: text, Tag: `json:"same"`},
		{Name: "Second", Type: text, Tag: `json:"same,omitempty"`},
	})
	if _, err := (generator{}).object(duplicate, false); err == nil || !strings.Contains(err.Error(), "the JSON field same is declared twice") {
		t.Fatalf("object error = %v, want the duplicate JSON name", err)
	}
}

func TestCheckTagsReportsEveryFieldWithoutAJSONName(t *testing.T) {
	t.Parallel()
	if err := CheckTags([]Type{{Name: "Everything", Value: fixtureEverything{}}, {Name: "Inner", Value: fixtureInner{}}}); err != nil {
		t.Fatalf("CheckTags of tagged structs = %v", err)
	}
	err := CheckTags([]Type{{Name: "Untagged", Value: fixtureUntagged{hidden: "unused"}}, {Name: "Embedded", Value: fixtureEmbedded{}}, {Name: "Number", Value: 1}})
	if err == nil {
		t.Fatal("CheckTags accepted fields without json tags")
	}
	for _, want := range []string{
		"apitypes.fixtureUntagged.Untagged: has no json tag",
		`apitypes.fixtureUntagged.Nameless: json tag ",omitempty" names no field`,
		"apitypes.fixtureUntagged.Nested.Inner: has no json tag",
		"apitypes.fixtureEmbedded.fixtureInner: embedded fields are not supported",
		"Number: int is not a struct",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckTags error = %v, want it to report %q", err, want)
		}
	}
	for _, unwanted := range []string{"Tagged:", "hidden", "Other"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("CheckTags error = %v, want no report of %s", err, unwanted)
		}
	}
}
