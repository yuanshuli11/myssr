package log

import (
	stdlog "log"
)

func init() {
	stdlog.SetFlags(stdlog.LstdFlags | stdlog.Lshortfile)
}

// Func defines a simple log function
type Func func(f string, v ...interface{})

// F is the main log function
var F Func = func(string, ...interface{}) {}

// Fatal log and exit
func Fatal(v ...interface{}) {
	stdlog.Fatal(v...)
}

// Fatalf log and exit
func Fatalf(f string, v ...interface{}) {
	stdlog.Fatalf(f, v...)
}
