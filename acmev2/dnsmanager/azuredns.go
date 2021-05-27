package dnsmanager

import "fmt"

/*

New-AzDnsZone -Name _acme-challenge.letsencrypt.ft.8daysaweek.cc -ResourceGroupName fileTransfer


New-AzDnsRecordSet -ZoneName _acme-challenge.letsencrypt.ft.8daysaweek.cc -ResourceGroupName fileTransfer `
 -Name "@" -RecordType "txt" -Ttl 600 `
 -DnsRecords (New-AzDnsRecordConfig -Value  "ncZ-Zxi_vktxUKVTK8LBWGZqSGeWZmylbw-QPQaeR7g")


*/

//CreateARecordAzureDNS tbd
func (d *AZUREDNSCredentials) CreateARecordAzureDNS(domain, ip string) (ok bool) {
	fmt.Println("CreateARecordAzureDNS(): ", domain, "->", ip, ".... using login/pw", d.Login, "/", d.Password)

	return true
}

//CreateTXTRecordAzureDNS tbd
func (d *AZUREDNSCredentials) CreateTXTRecordAzureDNS(domain, txt string) (ok bool) {
	fmt.Println("CreateTXTRecordAzureDNS(): ", domain, "<->", txt, ".... using login/pw", d.Login, "/", d.Password)

	return true
}
