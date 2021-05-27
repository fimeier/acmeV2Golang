package main

import (
	"flag"

	"gitlab.ethz.ch/fimeier/gostuff/acmev2/crypto/client"

	"gitlab.ethz.ch/fimeier/gostuff/acmev2/crypto/server"
	"gitlab.ethz.ch/fimeier/gostuff/acmev2/statemachine"
)

/*
	domain sollte eigentlich liste mit allen Domains für ein EINZELNES Zertifikat sein
	record ist die IP welche durch den DNS aufgelöst werden soll, wenn eine der Domänen abgefragt wird
		-> vermutlich nur für HTTP challenges relevant...

		---> ich ändere INTERFACE..... domainIP gibt die IP pro Domäne zurück, welche im DNS eingetragen sein sollte...
		---> ein Zertifikat kann mehrere Domänen enthalten welche auf unterschiedliche IPs zeigen
*/

var challengeType = flag.String("challengeType", "dns-01", "--challengeType dns-01 (http-01 or tls-alpn-01 are not implemented")

//var dir = flag.String("dir", "https://acme-v02.api.letsencrypt.org/directory", "--dir https://localhost:14000/dir")
var dir = flag.String("dir", "https://acme-staging-v02.api.letsencrypt.org/directory", "--dir https://localhost:14000/dir")

var record = flag.String("record", "tbd record", "--record") //eigentlich die IP für alle domains

//var domain = flag.String("domain", "test.ft.8daysaweek.cc;test2.ft.8daysaweek.cc", "--domain xyz.com;abc.com")
//var domainIP = flag.String("domainIP", "192.168.0.5;192.168.0.6", "--domainIP 192.168.0.5;192.168.0.6")

var domain = flag.String("domain", "ft.8daysaweek.cc", "--domain xyz.com;abc.com")
var domainIP = flag.String("domainIP", "51.154.53.165", "--domainIP 192.168.0.5;192.168.0.6")

var revoke = flag.Bool("revoke", false, "--revoke true")

func main() {
	//fmt.Println("Hi I am a very simple acmeV2 client for Let's Encrypt")

	flag.Parse()

	var a statemachine.ACMEInstance

	var k server.KeyInstance
	k.CreateRSAInstance()

	var ck client.KeyInstanceCert
	ck.CreateRSAInstance()

	a.CreateInstance(*challengeType, *dir, *domain, *domainIP, "azuredns", *revoke, k, ck)

	contact := []string{"mailto:letsencrypt@8daysaweek.cc"}

	//DNS Tests
	/*a.AZUREDNSTests()
	if 1 == 1 {
		return
	}*/

	a.Everything(contact)

	certFilePEM := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\certificates\\cert.pem"
	privateKeyPEM := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\certificates\\privateKey.pem"
	certFileCRT := "C:\\01Dropbox\\Dropbox\\200Programmierung\\gostuff\\pseudoFS\\certificates\\cert.crt"

	a.ExportCert(certFilePEM, privateKeyPEM, certFileCRT)

}
