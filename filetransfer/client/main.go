package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gitlab.ethz.ch/fimeier/gostuff/filetransfer/client/transfer"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var wg sync.WaitGroup

func main() {

	//start the client
	//filename := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\client1\\büsi.png"
	basefolder := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\client1\\sendthis\\"
	fmt.Println("Starting the client... using basefolder ", basefolder)

	err := filepath.Walk(basefolder, visit)
	check(err)

	wg.Wait()

}

func visit(filename string, info os.FileInfo, err error) error {

	if info.IsDir() { //ignore subdirectories for the moment
		return nil
	}

	wg.Add(1)
	go transfer.Send("http://10.80.45.73:4443/receiveData", filename, &wg)
	//fmt.Println("filename in visit=", filename)
	return nil
}
