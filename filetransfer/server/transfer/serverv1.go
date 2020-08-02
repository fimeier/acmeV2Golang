package transfer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.ethz.ch/fimeier/gostuff/filetransfer/encap"
)

var port int
var pathForFilesToStore string

var basefolderClient = "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\client1\\sendthis\\"

func check(e error) {
	if e != nil {
		panic(e)
	}
}

//Start starts a webserver on port portArgument to receive data
func Start(portArgument int, pathForFilesToStoreArgument string) {
	fmt.Println("Starting webserver on port ", portArgument)
	port = portArgument
	pathForFilesToStore = pathForFilesToStoreArgument

	http.HandleFunc("/receiveData", receiveDataHandler)
	http.HandleFunc("/", defaultHandler)
	addr := "10.80.45.73:" + strconv.Itoa(port)
	log.Fatal(http.ListenAndServe(addr, nil))

}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "URL.Path = %q\n", r.URL.Path)
}

func receiveDataHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("receiveDataHandler() called with URL.Path = ", r.URL.Path)

	//fmt.Println(r.Header) //debug

	if r.Method != "POST" {
		fmt.Println("Error: Not a POST method call....")
		w.WriteHeader(405)
		return
	}

	contentTypeTemp, ok := r.Header["Content-Type"]
	var contentType string
	if ok {
		contentType = contentTypeTemp[0] //wie direkt ohne temp?
	}
	switch contentType {
	case "tbd":
		fmt.Println("asd")
	case "application/json":
		fmt.Println("CASE contentType=", contentType)

		var receivedJSON encap.Lorem
		err := json.NewDecoder(r.Body).Decode(&receivedJSON)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Println("Type = ", receivedJSON.Type)
		fname := filepath.Base(receivedJSON.FileName)
		srcFolderClient := filepath.Dir(receivedJSON.FileName)

		filename := pathForFilesToStore + fname

		if srcFolderClient+"\\" != basefolderClient {
			fmt.Println("WARNING: srcFolderClient is different: ", srcFolderClient)
			//TODO change filename do include this....
			subfolder := strings.Split(srcFolderClient, basefolderClient)
			//fmt.Println(subfolder)

			filename = pathForFilesToStore + subfolder[1] + "\\" + fname

			err = os.MkdirAll(pathForFilesToStore+subfolder[1], 0755)
			check(err)

		}

		fmt.Println("Filename on Server: ", filename)

		f, err := os.Create(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send: %v\n", err)
			return
		}
		defer f.Close()
		//f.WriteString(receivedJSON.Content)

		pictureDecoded, _ := base64.StdEncoding.DecodeString(receivedJSON.Content)

		f.Write(pictureDecoded)

		w.WriteHeader(201)

	default:
		fmt.Println("default case contentType=", contentType)
		io.Copy(os.Stdout, r.Body)
	}

}
