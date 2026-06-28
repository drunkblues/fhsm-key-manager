package main

import (
	"errors"
	"os"

	"fhsm-key-manager/cmd"
	"fhsm-key-manager/internal/keymodel"
)

func main() {
	if err := cmd.Execute(); err != nil {
		var e *keymodel.Error
		if errors.As(err, &e) {
			keymodel.OutputError(e.Code, e.Msg)
		} else {
			keymodel.OutputError("INTERNAL", err.Error())
		}
		os.Exit(1)
	}
}
