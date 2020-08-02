package main

import (
	"fmt"

	"gitlab.ethz.ch/fimeier/gostuff/filetransfer/server/transfer"
)

func main() {
	//start the server
	fmt.Println("Starting the server...")
	pathForFilesToStore := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\server1\\"
	transfer.Start(4443, pathForFilesToStore)
}
