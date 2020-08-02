package transfer

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"gitlab.ethz.ch/fimeier/gostuff/filetransfer/encap"
)

//Send connects to a webserver on port portArgument to send filename
func Send(urlPort string, filename string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("Connecting to ", urlPort, "...", "and sending ", filename)

	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send: %v\n", err)
		return
	}
	defer f.Close()

	fmt.Println("using file ", f.Name())

	//get test returns a 405 status code
	/*
		resp, err := http.Get(urlPort)
		if err != nil {
			fmt.Println("An error: ", err.Error())
			return
		}
		defer resp.Body.Close()
		//print everything to stdout
		fmt.Println(resp.Status)
		io.Copy(os.Stdout, resp.Body)
	*/

	//post test

	jsonpupsi := encap.LoremIpsumJSON(f)
	//fmt.Printf("%s\n", jsonpupsi)

	resp, err := http.Post(urlPort, "application/json", bytes.NewReader(jsonpupsi))
	if err != nil {
		fmt.Println("An error: ", err.Error())
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
	io.Copy(os.Stdout, resp.Body)
}
