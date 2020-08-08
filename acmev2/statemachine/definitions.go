package statemachine

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gitlab.ethz.ch/fimeier/gostuff/acmev2/crypto/client"
	"gitlab.ethz.ch/fimeier/gostuff/acmev2/crypto/server"
	"gitlab.ethz.ch/fimeier/gostuff/acmev2/dnsmanager"
)

//ACMEInstance used for .... tbd
type ACMEInstance struct {
	challengeType string
	dirURL        string
	isWildCard    bool //wird ev indirekt benötigt
	domainList    []string
	ipForDomain   map[string]string
	revokeCert    bool
	serverKey     server.KeyInstance     //used to communicate with ACME server
	clientKey     client.KeyInstanceCert //used in cert

	certificate string //a pem certificate chain

	dnsManager dnsmanager.AZUREDNS

	//User Input
	contact []string //wird im PostNewAccount verwended

	//State Variables
	nonce               string
	meta                string //GetDirectory (vgl Java),..
	accountURL          string //für diesen spezifischen Account
	ordersURL           string //unklar ob das gebraucht wird...
	orderObjectLocation string
	ErrorDoc            ACMEError
	responseCode        int

	//orderObject ist geparster response body
	orderObject       OrderObject //orderObject, orderObjectByte, orderObjectString entspricht jeweils return body PostNewOrder() call
	orderObjectByte   []byte
	orderObjectString string

	authorizationObject     []AuthorizationObject //contains multiple objects for multiple challanges
	authorizationObjectByte [][]byte

	challengeStatusMap map[string]ChallengeStatus
	orderStatus        OrderStatus

	readyForFinalization bool
	readyForDownload     bool

	//durch GetDirectory() gesetzt
	newNonceURL   string
	newAccountURL string
	newOrderURL   string
	newAuthzURL   string
	revokeCertURL string
	keyChangeURL  string
}

//OrderStatus tbd
type OrderStatus struct {
	Status         string               `json:"status"`
	ErrorDoc       ACMEError            `json:"error"`
	Expires        string               `json:"expires"`
	Ident          []IdentiefierContent `json:"identifiers"`
	Finalize       string               `json:"finalize"`
	Authorizations []string             `json:"authorizations"`
	Certificate    string               `json:"certificate"`
}

//ChallengeStatus tbd
type ChallengeStatus struct {
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Token     string    `json:"token"`
	Status    string    `json:"status"`
	Validated string    `json:"validated"`
	ErrorDoc  ACMEError `json:"error"`
}

//ACMEError tbd
type ACMEError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

//OrderObject contains (complete) response Body of a PostNewOrder() call
type OrderObject struct {
	Status         string               `json:"status"`
	Expires        string               `json:"expires"`
	Ident          []IdentiefierContent `json:"identifiers"`
	Finalize       string               `json:"finalize"`
	Authorizations []string             `json:"authorizations"`
}

//AuthorizationObject contains (complete) response Body of a PostAsGetAuthorizationResources() call
type AuthorizationObject struct {
	Status     string              `json:"status"`
	Ident      IdentiefierContent  `json:"identifier"` //hier wirklich in der einzahl
	Challenges []ChallengesContent `json:"challenges"`
	Expires    string              `json:"expires"`
}

var supportedChallenges = map[string]bool{"dns-01": true}

//CreateInstance returns tbd...
//domains as a list test.ethz.ch;blubs.ethz.ch
func (a *ACMEInstance) CreateInstance(challenge, dir, domains, domainIPs, dnsManager string, revoke bool, serverK server.KeyInstance, clientK client.KeyInstanceCert) {

	if ok := supportedChallenges[challenge]; !ok {
		fmt.Fprintln(os.Stderr, "unsupported challengeType: ", challenge)
		os.Exit(2)
	}
	a.challengeType = challenge
	a.dirURL = dir
	a.domainList = strings.Split(domains, ";")

	ipList := strings.Split(domainIPs, ";")
	ipDom := make(map[string]string)
	for n, domain := range a.domainList {
		ipDom[domain] = ipList[n]
	}
	a.ipForDomain = ipDom

	if dnsManager == "azuredns" {
		a.dnsManager = dnsmanager.AZUREDNS{Login: "dummyuser",
			Password: "1234",
		}
	}

	a.revokeCert = revoke

	a.challengeStatusMap = make(map[string]ChallengeStatus)

	a.serverKey = serverK //used to communicate with ACME server
	a.clientKey = clientK

}

//ACMEHTTPsConnection contains everything for request/response
type ACMEHTTPsConnection struct {
	httpsURLConnection string
	responseCode       int
	connectionError    bool
	badNonce           bool
	responseHeader     http.Header

	//outputStream string //output or error

	hasJSONResponse    bool
	responseBodyByte   []byte
	responseBodyString string          //string(responseBodyByte)
	responseBodyMap    JSONResponseMap //TODO: z.B. für meta bei GetDirectory() funktioniert das nicht

}

//JSONResponseMap contains tbs
type JSONResponseMap map[string]interface{}

//CreateACMEHTTPsConnection tbd
/*
mode GET, downloadCert, POST
bytesToPutOnWire can be nil for GET method

TODO: Check for Return value or add second argument like ok
*/
func (a *ACMEInstance) CreateACMEHTTPsConnection(resourceURL string, bytesToPutOnWire []byte, httpMethod string) (returns *ACMEHTTPsConnection) {
	fmt.Fprintln(os.Stderr, "WARNING: CreateACMEHTTPsConnection() accepts all certs")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	returns = &ACMEHTTPsConnection{}

	var resp *http.Response
	var err error

	switch httpMethod {
	case "GET":
		//fmt.Println("GET case...")
		resp, err = http.Get(resourceURL)
		defer resp.Body.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "CreateACMEHTTPsConnection(): http.Get(", resourceURL, ") produced error = ", err.Error())
		}
	case "POST":
		resp, err = http.Post(resourceURL, "application/jose+json", bytes.NewReader(bytesToPutOnWire))
		defer resp.Body.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "CreateACMEHTTPsConnection(): http.Post(", resourceURL, ") produced error = ", err.Error())
		}
	case "downloadCert":
		resp, err = http.Post(resourceURL, "application/jose+json", bytes.NewReader(bytesToPutOnWire))
		defer resp.Body.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "CreateACMEHTTPsConnection(): http.Post(", resourceURL, ") produced error = ", err.Error())
		}
	default:
		fmt.Fprintln(os.Stderr, "CreateACMEHTTPsConnection(): unsupported httpMethod = ", httpMethod)
		os.Exit(2)
	}

	returns.responseCode = resp.StatusCode
	//fmt.Println("returns.responseCode=", returns.responseCode)
	contentLength, _ := strconv.Atoi(resp.Header.Get("Content-Length"))

	returns.responseHeader = resp.Header
	a.nonce = resp.Header.Get("Replay-Nonce") //always store the nonce
	//fmt.Println("a.nonce for next request=", a.nonce)

	if returns.responseCode == 400 || returns.responseCode == 403 {
		//TODO Handle 400 and 403 (compare JAVA code)
		fmt.Fprintln(os.Stderr, "CreateACMEHTTPsConnection(): TODO Handle 400 and 403 (until ************** is debug output)")
		for a, b := range resp.Header {
			fmt.Println(a, "=", b)
		}
		if contentLength > 0 {
			fmt.Println("contentLength > 0...............")
			returns.responseBodyByte, _ = ioutil.ReadAll(resp.Body)
			returns.responseBodyString = string(returns.responseBodyByte)
			fmt.Fprintln(os.Stderr, returns.responseBodyString)
			json.Unmarshal(returns.responseBodyByte, &returns.responseBodyMap)
			returns.checkForBadNonce()
			fmt.Fprintln(os.Stderr, "**************")

		}
		return returns
	}

	returns.responseBodyByte, _ = ioutil.ReadAll(resp.Body)
	returns.responseBodyString = string(returns.responseBodyByte)

	//downloadCert has no JSON response
	if httpMethod != "downloadCert" {
		returns.hasJSONResponse = true
		json.Unmarshal(returns.responseBodyByte, &returns.responseBodyMap)
	}

	returns.checkForBadNonce()

	return returns
}

func (c *ACMEHTTPsConnection) checkForBadNonce() {
	if typeResp := c.responseBodyMap["type"]; typeResp == "urn:ietf:params:acme:error:badNonce" {
		c.badNonce = true
		fmt.Println("checkForBadNonce(): bad nonce found!!!")
	}
}

//GetJSONContentByKey ...tbd TEST
func (jsonResponse *JSONResponseMap) GetJSONContentByKey(k string) (returns interface{}, ok bool) {
	//var v interface{}
	if returns, ok = (*jsonResponse)[k]; !ok {
		fmt.Println("Non existing key=", k)
		return nil, false
	}
	switch v := returns.(type) {
	case string:
		fmt.Println(k, "is string", v)
	case float64:
		fmt.Println(k, "is float64", v)
	case bool:
		fmt.Println(k, "is bool", v)
	case interface{}:
		s, _ := json.Marshal(v)
		fmt.Println(k, "is object", string(s))
	case []interface{}:
		fmt.Println(k, "is an array:")
		for i, u := range v {
			fmt.Println(i, u)
		}
	case nil:
		fmt.Println(k, "is nil", v) //gibts das?

	default:
		fmt.Println(k, "is of a type I don't know how to handle")

	}

	return returns, true

}

//IterateJSONContent ...tbd TEST
func (jsonResponse *JSONResponseMap) IterateJSONContent() {
	for k, v := range *jsonResponse {
		switch vv := v.(type) {
		case string:
			fmt.Println(k, "is string", vv)
		case float64:
			fmt.Println(k, "is float64", vv)
		case bool:
			fmt.Println(k, "is bool", vv)
		case interface{}:
			fmt.Println(k, "is an object/document containing:......")
			var embeddedJSON JSONResponseMap
			embeddedJSON = vv.(map[string]interface{}) //type assertion JSONResponseMap funktioniert nicht
			fmt.Println(embeddedJSON)
			embeddedJSON.IterateJSONContent()
		case []interface{}:
			fmt.Println(k, "is an array:")
			for i, u := range vv {
				fmt.Println(i, u)
			}
		case nil:
			fmt.Println(k, "is nil", vv) //gibts das?

		default:
			fmt.Println(k, "is of a type I don't know how to handle")

		}
	}

}

//ChallengesContent what
type ChallengesContent struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

//IdentiefierContent what goes into an Identifiers struc
type IdentiefierContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

//Identifiers an array on objects that the PostNewOrder pertains to
type Identifiers struct {
	Ident []IdentiefierContent `json:"identifiers"`
}

//NewAccountBody body part for newAccount step
type NewAccountBody struct {
	Contact                []string    `json:"contact,omitempty"`                //optional an array of string
	TermsOFServiceAgreed   bool        `json:"termsOFServiceAgreed,omitempty"`   //optional boolean
	OnlyReturnExisting     bool        `json:"onlyReturnExisting,omitempty"`     //optional
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"` //optional
}

//JWK is a JSON Web Key (for RSA )
type JWK struct {
	//REMARK: Fields are in correct order for thumbprint https://tools.ietf.org/pdf/rfc7638.pdf 3.1
	E   string `json:"e"` //as BigInteger Encoded (vgl JAVA)
	Kty string `json:"kty"`
	N   string `json:"n"` //as BigInteger Encoded
}

//CreateJWK returns JWK struct
func (a *ACMEInstance) CreateJWK() (jwk JWK) {

	//TODO Mode Switch for different crypto Primitives...
	var pkN *big.Int = (a.serverKey.PublicKey.(rsa.PublicKey)).N //ist vom type *big.Int... habe es absichtlich explizit hingeschrieben
	var pkE int = (a.serverKey.PublicKey.(rsa.PublicKey)).E      //type int

	pkNencoded := base64.RawURLEncoding.EncodeToString(pkN.Bytes())
	pkEencoded := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pkE)).Bytes())

	jwk = JWK{E: pkEencoded,
		Kty: "RSA",
		N:   pkNencoded,
	}

	return jwk
}

//ProtectedPartJWK tbd... (for RSA)
type ProtectedPartJWK struct {
	URL   string `json:"url"` //a resourceURL
	Jwk   JWK    `json:"jwk"`
	Nonce string `json:"nonce"` //always ACMEInstance.nonce
	Alg   string `json:"alg"`   //always "RS256"
}

//CreateProtectedPartJWK tbd
func (a *ACMEInstance) CreateProtectedPartJWK(jwk JWK, resourceURL string) (p []byte) {
	protectedPartJWK := ProtectedPartJWK{URL: resourceURL,
		Jwk:   jwk,
		Nonce: a.nonce,
		Alg:   "RS256",
	}
	p, _ = json.Marshal(protectedPartJWK)
	return p
}

//ProtectedPartKID tbd... (for RSA)
type ProtectedPartKID struct {
	URL   string `json:"url"`   //a resourceURL
	Kid   string `json:"kid"`   //always accountURL welche im PostNewAccount() definiert wird (fehlt noch)
	Nonce string `json:"nonce"` //always ACMEInstance.nonce
	Alg   string `json:"alg"`   //always "RS256"
}

//CreateProtectedPartKID tbd
func (a *ACMEInstance) CreateProtectedPartKID(resourceURL string) (p []byte) {
	protectedPartKID := ProtectedPartKID{URL: resourceURL,
		Kid:   a.accountURL,
		Nonce: a.nonce,
		Alg:   "RS256",
	}
	p, _ = json.Marshal(protectedPartKID)
	return p
}

//DataToPutOnWire on HTTPS POST operations
type DataToPutOnWire struct {
	Protected string `json:"protected"` //base64URLencoded
	Payload   string `json:"payload"`   //base64URLencoded
	Signature string `json:"signature"` //directly
}

//CreateDataToPutOnWire tbd
func CreateDataToPutOnWire(protectedPart, payloadPart []byte, signatureEncoded string) (returns DataToPutOnWire) {
	return DataToPutOnWire{Protected: base64.RawURLEncoding.EncodeToString(protectedPart),
		Payload:   base64.RawURLEncoding.EncodeToString(payloadPart),
		Signature: signatureEncoded}
}

//CreateSignatureString tbd
func (a *ACMEInstance) CreateSignatureString(protectedPart, payloadPart []byte) (signatureEncoded string) {
	signingString := base64.RawURLEncoding.EncodeToString(protectedPart) + "." + base64.RawURLEncoding.EncodeToString(payloadPart)
	//copied from https://golang.org/pkg/crypto/rsa/#SignPKCS1v15
	rng := rand.Reader
	message := []byte(signingString)
	hashed := sha256.Sum256(message)
	signature, _ := rsa.SignPKCS1v15(rng, a.serverKey.PrivateKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
	signatureEncoded = base64.RawURLEncoding.EncodeToString(signature)
	//fmt.Printf("signatureEncoded: %x\n", signatureEncoded)
	return signatureEncoded
}

//SignAndCreateDataToButOnWire is a combination of CreateSignatureString and CreateDataToPutOnWire
func (a *ACMEInstance) SignAndCreateDataToButOnWire(protectedPart, payloadPart []byte) (sendThis []byte) {
	signatureEncoded := a.CreateSignatureString(protectedPart, payloadPart)
	data := CreateDataToPutOnWire(protectedPart, payloadPart, signatureEncoded)
	sendThis, _ = json.Marshal(data)
	return sendThis
}

//CreatePostAsGetDataToPutOnWire tbd
func (a *ACMEInstance) CreatePostAsGetDataToPutOnWire(resourceURL string) (d []byte) {
	p := a.CreateProtectedPartKID(resourceURL)
	d = a.SignAndCreateDataToButOnWire(p, []byte(""))

	return d
}

//CreateThumbPrint tbd
func (a *ACMEInstance) CreateThumbPrint() (t string) {
	jwk := a.CreateJWK()
	j, _ := json.Marshal(jwk)

	//String thumbprint = getSHA256AsString(jkwAsString);
	//TODO apply hash to it

	t = GetSHA256(j)
	return t
}

//GetSHA256 tbd
func GetSHA256(data []byte) (h string) {
	a := sha256.Sum256(data)
	b := base64.RawURLEncoding.EncodeToString(a[:])
	return b
}

//CreateCSR tbd
func (a *ACMEInstance) CreateCSR() (csrDERBase64Encoded string) {

	u1, _ := url.Parse("http://whatTheHellIsThisFor.cc/search?q=dotnet")
	u2, _ := url.Parse("http://whatTheHellIsThisFor.ch/search?q=dotnet")

	template := x509.CertificateRequest{
		//SignatureAlgorithm: x509.SHA512WithRSAPSS,
		/*Subject: pkix.Name{
			CommonName:         "domain.com",
			Country:            []string{"AU"},
			Province:           []string{"Some-State"},
			Locality:           []string{"MyCity"},
			Organization:       []string{"Company Ltd"},
			OrganizationalUnit: []string{"IT"},
		},*/
		//EmailAddresses: []string{"test@email.com"}, //not supported in letsencrypt
		DNSNames: a.domainList, //[]string{"mydns1.local", "mydns2.local"},
		//IPAddresses:    []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")},
		URIs: []*url.URL{u1, u2},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, a.clientKey.PrivateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CreateCSR(): x509.CreateCertificateRequest(rand.Reader, &template, a.PrivateKey) failed with error: ", err.Error())
		return ""
	}

	csrDERBase64Encoded = base64.RawURLEncoding.EncodeToString(csr)
	return csrDERBase64Encoded
}

//CreateCSRRequestPart tbd
func (a *ACMEInstance) CreateCSRRequestPart() (csrJSON []byte) {
	csrStruc := CSRRequestPart{Csr: a.CreateCSR()}

	csrJSON, _ = json.Marshal(csrStruc)
	return csrJSON
}

//CSRRequestPart tbd
type CSRRequestPart struct {
	Csr string `json:"csr"`
}

//ExportCert exports the requested cert including the key
func (a *ACMEInstance) ExportCert(filenameCert, filenamePrivateKey string) {

	fmt.Println("Your new Cert is here.....")
	fmt.Println(a.certificate)
	f, err := os.Create(filenameCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send: %v\n", err)
		return
	}
	defer f.Close()
	f.WriteString(a.certificate)

	fmt.Println("the used Private Key was...")
	fmt.Println(a.clientKey.PrivateKeyPEM)
	f, err = os.Create(filenamePrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send: %v\n", err)
		return
	}
	defer f.Close()
	f.Write(a.clientKey.PrivateKeyPEM.Bytes())
	return
}
