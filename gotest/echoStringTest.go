// Copyright © 2016 Alan A. A. Donovan & Brian W. Kernighan.
// License: https://creativecommons.org/licenses/by-nc-sa/4.0/

// See page 8.

// Echo3 prints its command-line arguments.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

//!+
func main() {
	start := time.Now()
	fmt.Println(strings.Join(os.Args[0:], " "))
	miliSecs := time.Since(start).Milliseconds
	fmt.Printf("strings.Join took %dms\n", miliSecs)

	start = time.Now()
	s, sep := "", ""
	for _, arg := range os.Args[:] {
		s += sep + arg
		sep = " "
	}
	fmt.Println(s)
	fmt.Printf("oldschool took %dms\n", miliSecs)

}

//!-
