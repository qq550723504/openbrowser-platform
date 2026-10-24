package desktopauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Reject ambiguous duplicate members (including nested JWKS objects), huge nesting,
// and trailing values before decoding security-sensitive protocol documents.
func strictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > 1024*1024 || !utf8.Valid(data) {
		return ErrLogin
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := jsonValue(d, 0); err != nil {
		return ErrLogin
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrLogin
	}
	if exactFieldNames(data, reflect.TypeOf(target)) != nil {
		return ErrLogin
	}
	if err := json.Unmarshal(data, target); err != nil {
		return ErrLogin
	}
	return nil
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// encoding/json normally matches struct fields without case sensitivity. Reject
// aliases of known protocol members before that decode; unknown OIDC extensions
// remain valid. Apply the same rule inside typed JWKS arrays and local records.
func exactFieldNames(data []byte, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Implements(jsonUnmarshalerType) || reflect.PointerTo(typ).Implements(jsonUnmarshalerType) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var members map[string]json.RawMessage
		if json.Unmarshal(data, &members) != nil {
			return ErrLogin
		}
		for name, value := range members {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if !field.IsExported() {
					continue
				}
				canonical := strings.Split(field.Tag.Get("json"), ",")[0]
				if canonical == "-" {
					continue
				}
				if canonical == "" {
					canonical = field.Name
				}
				if strings.EqualFold(name, canonical) {
					if name != canonical || exactFieldNames(value, field.Type) != nil {
						return ErrLogin
					}
					break
				}
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if json.Unmarshal(data, &items) != nil {
			return ErrLogin
		}
		for _, item := range items {
			if exactFieldNames(item, typ.Elem()) != nil {
				return ErrLogin
			}
		}
	}
	return nil
}

func jsonValue(d *json.Decoder, depth int) error {
	if depth > 24 {
		return ErrLogin
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrLogin
			}
			seen[name] = true
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrLogin
		}
	case '[':
		for d.More() {
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrLogin
		}
	default:
		return ErrLogin
	}
	return nil
}
