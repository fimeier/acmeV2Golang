package statemachine

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

//AZUREDNSTests tbd
func (a *ACMEInstance) AZUREDNSTests() {
	fmt.Println("---------------------AZUREDNSTests()--------------------")

	/*
		fmt.Println("createing A-Record......")

		dnsRequest := a.dnsManager.PrepareAPIRequest("azuretest.ft.8daysaweek.cc", "51.154.53.165", "A")
		a.dnsRequest = dnsRequest

		c := a.CreateACMEHTTPsConnection(a.dnsRequest.ResourceURL, a.dnsRequest.Body, "PUT")

		fmt.Println("c.responseCode=", c.responseCode)
		fmt.Println("c.responseCode=", c.responseBodyString)
	*/

	fmt.Println("createing TXT-Record......")

	dnsRequest := a.dnsManager.PrepareAPIRequest("azuretest.ft.8daysaweek.cc", "huhu-im-a-Txt-record", "TXT")
	a.dnsRequest = dnsRequest
	a.dnsRequestCleanup = append(a.dnsRequestCleanup, a.dnsRequest)

	c := a.CreateACMEHTTPsConnection(a.dnsRequest.ResourceURL, a.dnsRequest.Body, "DELETE")

	fmt.Println("c.responseCode=", c.responseCode)
	fmt.Println("c.responseCode=", c.responseBodyString)

	/*if c.badNonce { //no such thing as a bad nonce
		fmt.Println("PostAsGetDownloadCert(): bad nonce, returning false")
		return false
	}*/
}

//Everything gets dir, creates accounts, and gets a cert. A proof of concept implementation for a state machine
func (a *ACMEInstance) Everything(contact []string) {
	//fmt.Println("Start Everything-State-Machine Test...")
	//implict durch compiler (*a).PrivateKeyPEM
	//fmt.Println(a.PrivateKeyPEM)

	a.contact = contact

	for !a.GetDirectory() {
	}

	a.GetANonce()
	for !a.PostNewAccount() {
	}

	//a.GetANonce()
	for !a.PostNewOrder() {
	}

	//a.GetANonce()
	for !a.PostAsGetAuthorizationResources() {
	}

	//a.GetANonce()
	for !a.FullFillChallenges() {
	}

	for !a.readyForFinalization {
		for !a.PostAsGetOrderStatus() {
		}
		time.Sleep(2 * time.Second)
	}

	for !a.FinalizeNewOrder() {
		if a.responseCode == 200 {
			break
		}
		if a.responseCode == 400 || a.responseCode == 403 {
			fmt.Fprintln(os.Stderr, "Everything(): FinalizeNewOrder() returned", a.responseCode)
			continue
		}
		fmt.Fprintln(os.Stderr, "FATAL: Everything(): FinalizeNewOrder() a.responseCode=", a.responseCode, "this shoould never happen")
	}

	for !a.readyForDownload {
		a.PostAsGetOrderStatus()
	}

	a.PostAsGetDownloadCert()

	a.CleanupChallenges()

}

//CleanupChallenges tbd
func (a *ACMEInstance) CleanupChallenges() (ok bool) {
	fmt.Println("---------------------CleanupChallenges()--------------------")
	for _, dnsRequest := range a.dnsRequestCleanup {
		a.dnsRequest = dnsRequest
		c := a.CreateACMEHTTPsConnection(a.dnsRequest.ResourceURL, a.dnsRequest.Body, "DELETE")

		fmt.Println("c.responseCode=", c.responseCode)
		fmt.Println("c.responseCode=", c.responseBodyString)

	}
	return true
}

//PostAsGetDownloadCert tbd
func (a *ACMEInstance) PostAsGetDownloadCert() (ok bool) {
	a.GetANonce()
	fmt.Println("---------------------PostAsGetDownloadCert()--------------------")

	resourceURL := a.orderStatus.Certificate
	fmt.Println("using resourceURL", resourceURL, "to download the cert")
	d := a.CreatePostAsGetDataToPutOnWire(resourceURL)

	c := a.CreateACMEHTTPsConnection(resourceURL, d, "downloadCert")
	if c.badNonce {
		fmt.Println("PostAsGetDownloadCert(): bad nonce, returning false")
		return false
	}

	//fmt.Println(c.responseBodyString)
	a.certificate = c.responseBodyString

	//TODO store the cert

	return true
}

//FinalizeNewOrder ...
func (a *ACMEInstance) FinalizeNewOrder() (ok bool) {
	a.GetANonce()
	fmt.Println("---------------------FinalizeNewOrder()--------------------")

	resourceURL := a.orderObject.Finalize

	p := a.CreateProtectedPartKID(resourceURL)
	//fmt.Println("protected part=", string(p))

	csr := a.CreateCSRRequestPart()
	//fmt.Print(string(csr))

	d := a.SignAndCreateDataToButOnWire(p, csr)

	c := a.CreateACMEHTTPsConnection(resourceURL, d, "POST")
	if c.badNonce {
		fmt.Println("FinalizeNewOrder(): bad nonce, returning false")
		return false
	}

	if c.responseCode == 400 || c.responseCode == 403 {
		json.Unmarshal(c.responseBodyByte, &a.ErrorDoc) //könnte man benutzen
		fmt.Fprintln(os.Stderr, "FinalizeNewOrder(): 403 returned. Cause\n: ", c.responseBodyString)
		a.responseCode = c.responseCode
		for a, b := range c.responseHeader {
			fmt.Fprintln(os.Stderr, a, "=", b)
		}
		return false
	}

	a.responseCode = c.responseCode

	fmt.Println(c.responseBodyString)

	return true
}

//PostAsGetOrderStatus tbd returns false in case of a wrong nonce. Always check the status
func (a *ACMEInstance) PostAsGetOrderStatus() (ok bool) {
	a.GetANonce()
	fmt.Println("---------------------PostAsGetOrderStatus()--------------------")

	d := a.CreatePostAsGetDataToPutOnWire(a.orderObjectLocation)

	c := a.CreateACMEHTTPsConnection(a.orderObjectLocation, d, "POST")
	if c.badNonce {
		fmt.Println("PostAsGetOrderStatus(): bad nonce, returning false")
		return false
	}

	//
	fmt.Println("respBodyString:", c.responseBodyString)

	//var orderStatus OrderStatus
	err := json.Unmarshal(c.responseBodyByte, &a.orderStatus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "PostAsGetOrderStatus(): json.Unmarshal((c.responseBodyByte, &orderStatus) failed with error: ", err.Error())
		return false
	}

	debug, _ := json.MarshalIndent(a.orderStatus, "", "   ")
	fmt.Println("parsedData", string(debug))

	fmt.Println("PostAsGetOrderStatus(): a.orderStatus.Status=", a.orderStatus.Status)

	switch a.orderStatus.Status {
	case "ready":
		{
			a.readyForFinalization = true
		}
	case "valid":
		{
			a.readyForDownload = true
		}
	case "invalid":
		{

		}
	case "pending":
		{

		}
	case "processing":
		{
			for a, b := range c.responseHeader {
				fmt.Println(a, "=", b)
			}
			//TODO Implement sleep
			waitTime := c.responseHeader.Get("Retry-After")
			fmt.Println("PostAsGetOrderStatus(): waitTime=", waitTime)
		}
	default:
		{
			fmt.Fprintln(os.Stderr, "PostAsGetOrderStatus(): a.orderStatus.Status is not implemented", a.orderStatus.Status)
		}
	}
	return true
}

//IsChallengeFullfilled tbd
func (a *ACMEInstance) IsChallengeFullfilled(challengeURL string) (ok bool) {
	a.GetANonce()
	fmt.Println("---------------------IsChallengeFullfilled()--------------------")

	d := a.CreatePostAsGetDataToPutOnWire(challengeURL)

	c := a.CreateACMEHTTPsConnection(challengeURL, d, "POST")
	if c.badNonce {
		fmt.Println("IsChallengeFullfilled(): bad nonce, returning false")
		return false
	}

	var challengeStatus ChallengeStatus
	err := json.Unmarshal(c.responseBodyByte, &challengeStatus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "IsChallengeFullfilled(): json.Unmarshal((c.responseBodyByte, &challengeStatus) failed with error: ", err.Error())
		return false
	}
	a.challengeStatusMap[challengeURL] = challengeStatus //store the status

	//debug, _ := json.MarshalIndent(a.challengeStatusMap[challengeURL], "", "   ")
	//fmt.Println(string(debug))

	//TODO Add logic
	if challengeStatus.Status == "Valid" {
		return true
	}
	return false
}

//FullFillChallenges ... sollten zwei FUnktionen sein, dann wäre StateMachine stabile
func (a *ACMEInstance) FullFillChallenges() (ok bool) {
	a.GetANonce()
	fmt.Println("---------------------FullFillChallenges()--------------------")

	//create A record for all domains (allways needed: unklar ob das Sinn macht)
	for n, domain := range a.domainList {
		fmt.Println(n+1, "domain =", domain)
		fmt.Println("Creating A record for ", domain, "->", a.ipForDomain[domain])

		//TODO remove wildcard in domain: *.example.com => example.com
		//TODO *example.com und example.com im selben Cert gibt Probleme mit Challenges
		a.dnsManager.CreateARecordAzureDNS(domain, a.ipForDomain[domain])
	}

	for _, authObj := range a.authorizationObject {
		ao, _ := json.MarshalIndent(authObj, "", "	")
		fmt.Println(string(ao))

		domain := authObj.Ident.Value
		var challengeURL string
		var token string

	Challenge:
		for _, challenge := range authObj.Challenges {
			//funktioniert nicht, da challengeURL, token dann nicht mehr definiert sind...
			if a.challangeCreated[challenge.URL] {
				fmt.Println("FullFillChallenges(): Challenge allready created for url", challenge.URL)
				challengeURL = challenge.URL
				continue
			}
			switch challenge.Type {
			case "dns-01":
				{
					if a.challengeType != "dns-01" {
						fmt.Println("FullFillChallenges(): Ignoring dns-01 challenge")
						continue
					}

					fmt.Println("FullFillChallenges(): Fullfilling dns-01 challenge")
					a.challangeCreated[challenge.URL] = true

					challengeURL = challenge.URL
					token = challenge.Token

					thumbPrint := a.CreateThumbPrint()
					keyAuthorization := token + "." + thumbPrint

					hashOfKeyAuthorization := GetSHA256([]byte(keyAuthorization))

					challengeDomain := "_acme-challenge." + domain

					//a.dnsManager.CreateTXTRecordAzureDNS(challengeDomain, hashOfKeyAuthorization)
					fmt.Println("createing TXT-Record......")

					dnsRequest := a.dnsManager.PrepareAPIRequest(challengeDomain, hashOfKeyAuthorization, "TXT")
					a.dnsRequest = dnsRequest
					a.dnsRequestCleanup = append(a.dnsRequestCleanup, a.dnsRequest)

					c := a.CreateACMEHTTPsConnection(a.dnsRequest.ResourceURL, a.dnsRequest.Body, "PUT")

					fmt.Println("c.responseCode=", c.responseCode)
					fmt.Println("c.responseCode=", c.responseBodyString)

					break Challenge //escape from challenge loop, as only one challange will be fullfilled
				}
			case "http-01":
				{
					if a.challengeType != "http-01" {
						fmt.Println("FullFillChallenges(): Ignoring http01 challenge")
						continue
					}

					break Challenge //escape from challenge loop, as only one challange will be fullfilled
				}
			case "tls-alpn-01":
				{
					if a.challengeType != "tls-alpn-01" {
						fmt.Println("FullFillChallenges(): Ignoring tls-alpn-01 challenge")
						continue
					}

					break Challenge //escape from challenge loop, as only one challange will be fullfilled
				}
			default:
				fmt.Fprintln(os.Stderr, "WARNING: FullFillChallenges(): Unknown challengeType=", challenge.Type)
				continue
			}

		}

		fmt.Println("INFO: Challenge", a.challengeType, "for domain", domain, "using URL", challengeURL, "and token", token)

		/*
			HIER scheint jeweils eine frische nonce nötig zu sein, da die alte abgelaufen ist
		*/
		//a.GetANonce()

		p := a.CreateProtectedPartKID(challengeURL)
		//fmt.Println("protected part=", string(p))

		d := a.SignAndCreateDataToButOnWire(p, []byte("{}"))

		c := a.CreateACMEHTTPsConnection(challengeURL, d, "POST")
		if c.badNonce {
			fmt.Println("PostNewAccount(): bad nonce, returning false")
			return false
		}

		fmt.Println(c.responseBodyString)

		a.IsChallengeFullfilled(challengeURL)
	}

	return true
}

//PostAsGetAuthorizationResources ....
func (a *ACMEInstance) PostAsGetAuthorizationResources() (ok bool) {
	fmt.Println("---------------------PostAsGewtAuthorizationResources()--------------------")

	for n, authURL := range a.orderObject.Authorizations {
		fmt.Println(n+1, "-authURL=", authURL)
		d := a.CreatePostAsGetDataToPutOnWire(authURL)

		c := a.CreateACMEHTTPsConnection(authURL, d, "POST")
		if c.badNonce {
			fmt.Println("PostNewAccount(): bad nonce, returning false")
			return false
		}

		a.authorizationObjectByte = append(a.authorizationObjectByte, c.responseBodyByte)
		var authObj AuthorizationObject
		err := json.Unmarshal(c.responseBodyByte, &authObj)
		if err != nil {
			fmt.Fprintln(os.Stderr, "PostAsGetAuthorizationResources(): json.Unmarshal(c.responseBodyByte, &(a.authorizationObject) failed with error: ", err.Error())
			return false
		}
		a.authorizationObject = append(a.authorizationObject, authObj)

		//ao, _ := json.MarshalIndent(authObj, "", "	")
		//fmt.Println(string(ao))
	}

	return true
}

//PostNewOrder tbd
func (a *ACMEInstance) PostNewOrder() (ok bool) {
	fmt.Println("---------------------PostNewOrder()--------------------")

	identifiers := Identifiers{}
	for _, domain := range a.domainList {
		cont := IdentiefierContent{Type: "dns",
			Value: domain}
		identifiers.Ident = append(identifiers.Ident, cont)
	}

	i, _ := json.Marshal(identifiers)
	fmt.Println("identifiers=", string(i))

	p := a.CreateProtectedPartKID(a.newOrderURL)
	//fmt.Println("protected part=", string(p))

	d := a.SignAndCreateDataToButOnWire(p, i)

	c := a.CreateACMEHTTPsConnection(a.newOrderURL, d, "POST")
	if c.badNonce {
		fmt.Println("PostNewAccount(): bad nonce, returning false")
		return false
	}

	a.orderObjectLocation = c.responseHeader.Get("Location") //spezific for this order

	a.orderObjectByte = c.responseBodyByte
	err := json.Unmarshal(c.responseBodyByte, &(a.orderObject))
	if err != nil {
		fmt.Fprintln(os.Stderr, "PostNewOrder(): json.Unmarshal(c.responseBodyByte, &(a.orderObject) failed with error: ", err.Error())
		fmt.Fprintln(os.Stderr, "Content c.responseBodyByte=", string(c.responseBodyByte))
		return false
	}

	return true
}

//PostNewAccount does bööö
func (a *ACMEInstance) PostNewAccount() (ok bool) {
	fmt.Println("---------------------PostNewAccount()--------------------")

	body := NewAccountBody{Contact: a.contact,
		TermsOFServiceAgreed: true}

	b, _ := json.Marshal(body)
	//fmt.Println("bodypart=", string(b))

	//TODO Mode Switch for different crypto Primitives...
	jwk := a.CreateJWK()

	p := a.CreateProtectedPartJWK(jwk, a.newAccountURL)

	d := a.SignAndCreateDataToButOnWire(p, b)

	c := a.CreateACMEHTTPsConnection(a.newAccountURL, d, "POST")
	if c.badNonce {
		fmt.Println("PostNewAccount(): bad nonce, returning false")
		return false
	}

	//fmt.Println("------------response was.............:\n", c.responseBodyString)

	a.accountURL = c.responseHeader.Get("Location") //save account url (this new account)
	if r, ok := c.responseBodyMap.GetJSONContentByKey("orders"); ok {
		a.ordersURL = r.(string)
	}

	return true
}

//GetDirectory tbd
func (a *ACMEInstance) GetDirectory() (ok bool) {
	fmt.Println("---------------------GetDirectory()--------------------")

	/* JAVA CODE
	AcmeHTTPsConnection acmeConnection = new AcmeHTTPsConnection();
	acmeConnection.connect(dirUrl, null, "GET");
	JsonObject responseJson = acmeConnection.responseJson;
	*/

	c := a.CreateACMEHTTPsConnection(a.dirURL, nil, "GET")
	if c.badNonce {
		fmt.Println("GetDirectory(): bad nonce, returning false")
		return false
	}
	//parse the response

	//check results?
	//parse it directly into struct?
	if r, ok := c.responseBodyMap.GetJSONContentByKey("newNonce"); ok {
		a.newNonceURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("newAccount"); ok {
		a.newAccountURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("newOrder"); ok {
		a.newOrderURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("newAuthz"); ok {
		a.newAuthzURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("revokeCert"); ok {
		a.revokeCertURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("keyChange"); ok {
		a.keyChangeURL = r.(string)
	}

	if r, ok := c.responseBodyMap.GetJSONContentByKey("meta"); ok {
		s, _ := json.Marshal(r)
		a.meta = string(s)
	}

	return true
}

//GetANonce tbd
func (a *ACMEInstance) GetANonce() {
	fmt.Println("---------------------GetANonce()--------------------")

	a.CreateACMEHTTPsConnection(a.newNonceURL, nil, "GET")
}
