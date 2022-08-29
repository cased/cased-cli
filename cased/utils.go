package cased

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
)

// SerializeParams serializes any given struct or map to a proper url.Values{} object.
// If a json tag is present for a given struct field, it will be used as the
// parameter name, otherwise the struct's field name is used.
// Private tags "-" are skipped.
func SerializeParams(obj interface{}) (url.Values, error) {
	t := reflect.TypeOf(obj).Elem()
	v := reflect.ValueOf(obj).Elem()

	// Build URL params from struct/map using reflection.
	params := url.Values{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")

		// skip private tags
		if tag == "-" {
			continue
		}

		if tag == "" {
			tag = sf.Name
		}

		fieldValue := v.Field(i)

		switch fieldValue.Kind() {
		case reflect.String:
			params.Add(tag, fieldValue.String())
		case reflect.Int:
			params.Add(tag, strconv.FormatInt(fieldValue.Int(), 10))
		case reflect.Bool:
			bv := fieldValue.Bool()
			if bv {
				params.Add(tag, "True")
			} else {
				params.Add(tag, "False")
			}
		case reflect.Map:
			mp := make(map[string]interface{})
			for _, e := range fieldValue.MapKeys() {
				mv := fieldValue.MapIndex(e)
				switch t := mv.Interface().(type) {
				default:
					mp[e.String()] = t
				}
			}

			jstr, err := json.Marshal(mp)
			if err != nil {
				return nil, err
			}
			params.Add(tag, string(jstr))
		case reflect.Slice:
			if fieldValue.IsNil() {
				params.Add(tag, "")
			} else {
				sv := make([]interface{}, fieldValue.Len())

				for i := 0; i < fieldValue.Len(); i++ {
					sv[i] = fieldValue.Index(i).Interface()
				}

				jstr, err := json.Marshal(sv)
				if err != nil {
					return nil, err
				}
				params.Add(tag, string(jstr))
			}
		default:
			return nil, errors.New(fmt.Sprintf("Unknown kind: %v", fieldValue.Kind()))
		}
	}

	// fmt.Println("SERIALIZED", params)
	return params, nil
}
