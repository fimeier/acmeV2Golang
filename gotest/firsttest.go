package main2

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// Rulps the very first test
func Rulps(d int) (returns int) {
	rand.Seed(int64(time.Now().UnixNano()))

	returns = d + rand.Intn(100)

	return returns
}

func main2() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":4443", nil))
}

//!+handler
// handler echoes the HTTP request.
func handler(w http.ResponseWriter, r *http.Request) {

	filename := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\juhu.txt"
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("%t", err)
	}

	fmt.Fprintf(w, string(dat))

	var d = Rulps(42)

	fmt.Printf("%d", d)
	fmt.Printf(string(dat))

	fmt.Fprintf(w, "\ndies ist ein Testli %d", d)
	fmt.Fprintf(w, "\nhallo %d\n", d)
}
