# Pig - A DNS Intelligence Tool

Pig is a DNS information gathering tool that allows you to retrieve and make inferences about various types of DNS records for a given domain. With Pig, you can quickly retrieve the A, AAAA, NS, MX, TXT, CNAME, SRV, SPF, PTR, and Reverse Lookup records for a domain in an easy human-readable report. 

## Features

- Retrieve A, AAAA, NS, MX, TXT, CNAME, SRV, SPF, PTR, and Reverse Lookup records
- Easy to use, simply provide the domain name as an argument

## Installation

1. Clone the repository: `git clone https://github.com/donuts-are-good/pig.git`
2. Change into the project directory: `cd pig`
3. Build the project: `go build`

## Usage

To use Pig, simply provide the domain name as an argument:

```
./pig example.com
```

## Example Output

```
$ pig github.com 
```
```
[A & AAAA Records]
140.82.113.3
-  Country: US, Region: Washington, D.C., City: Washington
-  IP 140.82.113.3 is listed on blacklist: zen.spamhaus.org

[CNAME Record] github.com.

[CNAME Subdomain Redirection]
Redirects to: github.com.

[Inferred Services or Platforms]
github.com.: Other

[MX Records]
Google Workspace: aspmx.l.google.com. 1
Google Workspace: alt1.aspmx.l.google.com. 5
Google Workspace: alt2.aspmx.l.google.com. 5
Google Workspace: alt4.aspmx.l.google.com. 10
Google Workspace: alt3.aspmx.l.google.com. 10

[Email Service Providers]
Google Workspace: aspmx.l.google.com.
Google Workspace: alt1.aspmx.l.google.com.
Google Workspace: alt2.aspmx.l.google.com.
Google Workspace: alt4.aspmx.l.google.com.
Google Workspace: alt3.aspmx.l.google.com.

[NS Records]
Other: dns1.p08.nsone.net.
Other: dns2.p08.nsone.net.
Other: dns3.p08.nsone.net.
Other: dns4.p08.nsone.net.
AWS Route 53: ns-1283.awsdns-32.org.
AWS Route 53: ns-1707.awsdns-21.co.uk.
AWS Route 53: ns-421.awsdns-52.com.
AWS Route 53: ns-520.awsdns-01.net.

[DNS Service Providers]
Other: dns1.p08.nsone.net.
Other: dns2.p08.nsone.net.
Other: dns3.p08.nsone.net.
Other: dns4.p08.nsone.net.
AWS Route 53: ns-1283.awsdns-32.org.
AWS Route 53: ns-1707.awsdns-21.co.uk.
AWS Route 53: ns-421.awsdns-52.com.
AWS Route 53: ns-520.awsdns-01.net.

[PTR Records]
lb-140-82-113-3-iad.github.com.

[Reverse Lookup]
lb-140-82-113-3-iad.github.com.

[SPF Records]
v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com include:spf.protection.outlook.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ip4:167.89.101.2 ip4:167.89.101.192/28 ip4:192.254.112.60 ip4:192.254.112.98/31 ip4:192.254.113.10 ip4:192.254.113.101 ip4:192.254.114.176 ip4:62.253.227.114 ~all

[SPF Allowed IPs and Mechanisms]
192.30.252.0/22
include:_netblocks.google.com
include:_netblocks2.google.com
include:_netblocks3.google.com
include:spf.protection.outlook.com
include:mail.zendesk.com
include:_spf.salesforce.com
include:servers.mcsv.net
166.78.69.169
166.78.69.170
166.78.71.131
167.89.101.2
167.89.101.192/28
192.254.112.60
192.254.112.98/31
192.254.113.10
192.254.113.101
192.254.114.176
62.253.227.114
~all

[TXT Records]
MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805
MS=ms44452932
MS=ms58704441
adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b
apple-domain-verification=RyQhdzTl6Z6x8ZP4
atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8
docusign=087098e3-3d46-47b7-9b4e-8a23028154cd
facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50
google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o
krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE
loom-site-verification=f3787154f1154b7880e720a511ea664d
stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f
v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com include:spf.protection.outlook.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ip4:167.89.101.2 ip4:167.89.101.192/28 ip4:192.254.112.60 ip4:192.254.112.98/31 ip4:192.254.113.10 ip4:192.254.113.101 ip4:192.254.114.176 ip4:62.253.227.114 ~all

```

## Contributing

If you would like to contribute to Pig, simply fork the repository and submit a pull request. We welcome all contributions, big or small.

## License

Pig is released under the MIT license. See [LICENSE](https://github.com/donuts-are-good/pig/blob/master/LICENSE.md) for more information.
