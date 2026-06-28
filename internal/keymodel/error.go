package keymodel

import (
	"encoding/json"
	"fmt"
	"os"
)

type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }
func NewError(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

func OutputJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func OutputError(code, msg string) {
	OutputJSON(struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{Error: msg, Code: code})
}
