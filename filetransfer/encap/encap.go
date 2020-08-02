package encap

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

//Lorem struct to test filetransfer with lorem ipsum
type Lorem struct {
	Type        string
	ContentSize int
	Content     string
	FileName    string
	FilePath    string
}

//LoremIpsum return Lorem struct to test filetransfer with lorem ipsum
func LoremIpsum(f *os.File) (result Lorem) {
	content, err := ioutil.ReadFile(f.Name())
	if err != nil {
		log.Fatal(err)
	}

	contentBase64 := base64.StdEncoding.EncodeToString(content)

	result = Lorem{
		Type:        "string",
		ContentSize: len(contentBase64), //anpassen auf Encoding
		Content:     contentBase64,
		FileName:    f.Name(),
	}
	return result
}

//LoremIpsumJSON return Lorem json to test filetransfer with lorem ipsum
func LoremIpsumJSON(f *os.File) (data []byte) {
	data, err := json.Marshal(LoremIpsum(f))
	if err != nil {
		log.Fatalf("JSON marshaling failed: %s", err)
	}

	return data
}
