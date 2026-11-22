package pedigree

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxJSONDepth = 10000
const maxSafeInteger = 1<<53 - 1

var errJSON = errors.New("invalid JCS input")

func serializeJCS(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeJCS(&out, reflect.ValueOf(v), 0, false); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// serializeArgsJCS uses RFC 8785 binary64 rounding for every argument number.
func serializeArgsJCS(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeJCS(&out, reflect.ValueOf(v), 0, true); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeJCS(out *bytes.Buffer, v reflect.Value, depth int, args bool) error {
	if depth > maxJSONDepth {
		return errJSON
	}
	if !v.IsValid() {
		out.WriteString("null")
		return nil
	}
	if v.Kind() == reflect.Interface {
		return writeJCS(out, v.Elem(), depth, args)
	}
	if v.Type() == reflect.TypeOf(json.Number("")) {
		if args {
			s := v.String()
			if !json.Valid([]byte(s)) {
				return errJSON
			}
			n, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return errJSON
			}
			return writeNumber(out, n)
		}
		n, ok := parseJSONNumber(v.String())
		if !ok {
			return errJSON
		}
		return writeNumber(out, n)
	}
	switch v.Kind() {
	case reflect.String:
		return writeString(out, v.String())
	case reflect.Bool:
		out.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Float32, reflect.Float64:
		return writeNumber(out, v.Float())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if args {
			return writeNumber(out, float64(n))
		}
		if n > maxSafeInteger || n < -maxSafeInteger {
			return errJSON
		}
		out.WriteString(strconv.FormatInt(n, 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		if args {
			return writeNumber(out, float64(n))
		}
		if n > maxSafeInteger {
			return errJSON
		}
		out.WriteString(strconv.FormatUint(n, 10))
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return errJSON
		}
		if v.IsNil() {
			out.WriteString("null")
			return nil
		}
		return writeObject(out, v, depth, args)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			out.WriteString("null")
			return nil
		}
		out.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCS(out, v.Index(i), depth+1, args); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		return errJSON
	}
	return nil
}

func writeObject(out *bytes.Buffer, v reflect.Value, depth int, args bool) error {
	type member struct {
		key   reflect.Value
		order []uint16
	}
	members := make([]member, 0, v.Len())
	for _, key := range v.MapKeys() {
		if !utf8.ValidString(key.String()) {
			return errJSON
		}
		members = append(members, member{key, utf16.Encode([]rune(key.String()))})
	}
	slices.SortFunc(members, func(a, b member) int { return slices.Compare(a.order, b.order) })
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeString(out, m.key.String()); err != nil {
			return err
		}
		out.WriteByte(':')
		if err := writeJCS(out, v.MapIndex(m.key), depth+1, args); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

func writeString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errJSON
	}
	const hexDigits = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(byte(r))
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[r>>4])
				out.WriteByte(hexDigits[r&15])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

func writeNumber(out *bytes.Buffer, n float64) error {
	if math.IsInf(n, 0) || math.IsNaN(n) {
		return errJSON
	}
	if n == 0 {
		out.WriteByte('0')
		return nil
	}
	// encoding/json uses the ECMAScript cutoffs and shortest binary64 spelling.
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	out.Write(b)
	return nil
}

func parseJSONNumber(s string) (float64, bool) {
	if !json.Valid([]byte(s)) {
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	if math.Abs(n) >= 1<<53 && decimalInteger(s) {
		return 0, false
	}
	return n, true
}

// decimalInteger tests the original decimal spelling before binary64 rounding.
func decimalInteger(s string) bool {
	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(s), "e")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimRight(whole+fraction, "0")
	power := 0
	if hasExponent {
		var err error
		power, err = strconv.Atoi(exponent)
		if err != nil {
			return !strings.HasPrefix(exponent, "-")
		}
	}
	return power >= len(digits)-len(whole)
}

func decodeObject(data []byte) (map[string]any, string) {
	if !utf8.Valid(data) || !validSurrogates(data) {
		return nil, "malformed"
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := readJSONValue(d, 0)
	if err != nil {
		return nil, "malformed"
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, "malformed"
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, "malformed"
	}
	canonical, err := serializeJCS(obj)
	if err != nil {
		return nil, "malformed"
	}
	if !bytes.Equal(data, canonical) {
		return obj, "non_canonical"
	}
	return obj, ""
}

// encoding/json replaces lone escaped surrogates with U+FFFD. Reject them
// before decoding so a malformed escape cannot become a member name or value.
func validSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || i+1 >= len(data) {
				return false
			}
			i++
			if data[i] != 'u' {
				continue
			}
			first, ok := hexEscape(data[i+1:])
			if !ok || 0xdc00 <= first && first <= 0xdfff {
				return false
			}
			i += 4
			if 0xd800 <= first && first <= 0xdbff {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				next, ok := hexEscape(data[i+3:])
				if !ok || next < 0xdc00 || next > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

func hexEscape(data []byte) (uint64, bool) {
	if len(data) < 4 {
		return 0, false
	}
	for _, b := range data[:4] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(b)) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(string(data[:4]), 16, 16)
	return n, err == nil
}

func readJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errJSON
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		return readJSONObject(d, depth)
	case json.Delim('['):
		items := []any{}
		for d.More() {
			item, err := readJSONValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, readEnd(d, ']')
	default:
		if n, ok := t.(json.Number); ok {
			value, valid := parseJSONNumber(string(n))
			if !valid {
				return nil, errJSON
			}
			return value, nil
		}
		return t, nil
	}
}

func readJSONObject(d *json.Decoder, depth int) (map[string]any, error) {
	obj := map[string]any{}
	for d.More() {
		member, err := d.Token()
		name, ok := member.(string)
		if err != nil || !ok {
			return nil, errJSON
		}
		if _, exists := obj[name]; exists {
			return nil, errJSON
		}
		value, err := readJSONValue(d, depth+1)
		if err != nil {
			return nil, err
		}
		obj[name] = value
	}
	return obj, readEnd(d, '}')
}

func readEnd(d *json.Decoder, want json.Delim) error {
	end, err := d.Token()
	if err != nil || end != want {
		return errJSON
	}
	return nil
}
