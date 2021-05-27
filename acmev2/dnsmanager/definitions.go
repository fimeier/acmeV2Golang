package dnsmanager

import (
	"encoding/json"
	"fmt"
	"strings"
)

//AZUREDNSCredentials tbd
type AZUREDNSCredentials struct {
	Login          string
	Password       string
	SubscriptionID string
	ResourceGroups string
	Authorization  string
}

//CreateAZUREDNSCredentials tbd Wird bei CreateInstance bereits direkt gesetzt
/*
func (c *AZUREDNSCredentials) CreateAZUREDNSCredentials() {
	c.SubscriptionID = "9fa587f1-4961-48a6-b6f6-ec69c6d724f1"
	c.ResourceGroups = "fileTransfer"
	c.Authorization = "Bearer tbd"
}*/

//DNSConfigurationRequest tbd
type DNSConfigurationRequest struct {
	ResourceURL string
	Header      map[string]string
	Body        []byte
}

//`json:"contact,omitempty"`

//AZUREMetadata tbd
type AZUREMetadata struct {
	Key1 string `json:"key1"`
}

//IPV4AddressContent tbd
type IPV4AddressContent struct {
	Ipv4Address string `json:"ipv4Address"`
}

//TXTRecordContent tbd
type TXTRecordContent struct {
	Value []string `json:"value"`
}

/*//TXTValue tbd
type TXTValue struct {
	Value []string `json:"value"`
}*/

//DNSRequestBodyPropertiesContent tbd
type DNSRequestBodyPropertiesContent struct {
	Metadata   AZUREMetadata        `json:"metadata"`
	TTL        int                  `json:"TTL"`
	ARecords   []IPV4AddressContent `json:"ARecords,omitempty"`
	TXTRecords []TXTRecordContent   `json:"TXTRecords,omitempty"`
}

//DNSRequestBodyProperties tbd
type DNSRequestBodyProperties struct {
	Properties DNSRequestBodyPropertiesContent `json:"properties"`
	/*{
			"properties": {
			  "metadata": {
				"key1": "value1"
			  },
			  "TTL": 3600,
			  "ARecords": [
				{
				  "ipv4Address": "127.0.0.1"
				}
			  ]
			}
		  }
	}*/

	/*
			{
		  "properties": {
		    "metadata": {
		      "key1": "value1"
		    },
		    "TTL": 3600,
		    "TXTRecords": [
		      {
		        "value": [
		          "string1",
		          "string2"
		        ]
		      }
		    ]
		  }
		}*/
}

//PrepareAPIRequest dbs
func (c *AZUREDNSCredentials) PrepareAPIRequest(name, value, typeOfEntry string) (returns DNSConfigurationRequest) {
	fmt.Println("---------------------PrepareAPIRequest()--------------------")

	returns = DNSConfigurationRequest{Header: make(map[string]string)}

	domainSlice := strings.SplitN(name, ".", 2)
	relativeRecordSetName := domainSlice[0]
	zoneName := domainSlice[1]

	urlPrefix := "https://management.azure.com/subscriptions/" + c.SubscriptionID + "/resourceGroups/" + c.ResourceGroups + "/providers/Microsoft.Network/dnsZones/" + zoneName
	urlPostfix := "?api-version=2018-05-01"

	returns.Header["Content-Type"] = "application/json"
	returns.Header["Authorization"] = c.Authorization

	var content DNSRequestBodyProperties

	switch typeOfEntry {
	case "A":
		//https: //management.azure.com/subscriptions/9fa587f1-4961-48a6-b6f6-ec69c6d724f1/resourceGroups/fileTransfer/providers/Microsoft.Network/dnsZones/ft.8daysaweek.cc/A/postmantest?api-version=2018-05-01

		returns.ResourceURL = urlPrefix + "/A/" + relativeRecordSetName

		//ARecord := IPV4AddressContent{Ipv4Address: "1.2.3.4"}
		//temp := DNSRequestBodyPropertiesContent{TTL: 6, ARecords: []IPV4AddressContent{IPV4AddressContent{Ipv4Address: "1.2.3.4"}}}

		content = DNSRequestBodyProperties{Properties: DNSRequestBodyPropertiesContent{
			Metadata: AZUREMetadata{
				Key1: "value1",
			},
			TTL: 6,
			ARecords: []IPV4AddressContent{
				IPV4AddressContent{Ipv4Address: value}},
		}}

	case "TXT":
		returns.ResourceURL = urlPrefix + "/TXT/" + relativeRecordSetName

		content = DNSRequestBodyProperties{Properties: DNSRequestBodyPropertiesContent{
			Metadata: AZUREMetadata{
				Key1: "value1",
			},
			TTL: 6,
			TXTRecords: []TXTRecordContent{
				TXTRecordContent{Value: []string{value}},
			},
		}}
	}

	returns.Body, _ = json.MarshalIndent(content, "", "   ")

	returns.ResourceURL += urlPostfix

	fmt.Println("returns.ResourceURL=", returns.ResourceURL)
	fmt.Println("returns.Header Fields...")
	for k, v := range returns.Header {
		fmt.Println(k, "=", v)
	}
	fmt.Println("returns.Body=", string(returns.Body))

	return returns
}
