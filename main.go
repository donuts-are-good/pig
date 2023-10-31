package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(os.Args[0], "domain")
		os.Exit(1)
	}
	domain := os.Args[1]
	aRecords(domain)
	aaaaRecords(domain)
	cnameRecords(domain)
	mxRecords(domain)
	nsRecords(domain)
	ptrRecords(domain)
	reverseLookup(domain)
	spfRecords(domain)
	srvRecords(domain)
	txtRecords(domain)
}

func aRecords(domain string) {
	ips, _ := net.LookupIP(domain)
	if len(ips) < 1 {
		return
	}
	fmt.Println("\n[A & AAAA Records]")
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			fmt.Println(ipv4.String())
			ipGeolocation(ipv4)
			asnLookup(ipv4)
			checkBlacklist(ipv4)
		}
	}
}

func aaaaRecords(domain string) {
	ips, _ := net.LookupIP(domain)
	if len(ips) < 1 {
		return
	}

	for _, ip := range ips {
		if ipv6 := ip.To16(); ipv6 != nil && ip.To4() == nil {
			fmt.Println("AAAA: " + ip.String())
		}
	}
}

func mxRecords(domain string) {
	mxRecords, _ := net.LookupMX(domain)
	if len(mxRecords) < 1 {
		return
	}
	fmt.Println("\n[MX Records]")
	for _, mx := range mxRecords {
		service := detectService(mx.Host)
		fmt.Printf("%s: %s %v\n", service, mx.Host, mx.Pref)
	}
	analyzeMX(mxRecords)
}

func nsRecords(domain string) {
	nameservers, _ := net.LookupNS(domain)
	if len(nameservers) < 1 {
		return
	}
	fmt.Println("\n[NS Records]")
	for _, ns := range nameservers {
		service := detectService(ns.Host)
		fmt.Printf("%s: %s\n", service, ns.Host)
	}
	analyzeNS(nameservers)
}

func srvRecords(domain string) {
	_, srvAddrs, err := net.LookupSRV("", "", domain)
	if len(srvAddrs) < 1 {
		return
	}
	if err != nil {
		return
	}
	fmt.Println("\n[SRV Records]")
	for _, srvAddr := range srvAddrs {
		fmt.Printf("%s:%d %d %d\n", srvAddr.Target, srvAddr.Port, srvAddr.Priority, srvAddr.Weight)
	}
	analyzeSRV(srvAddrs)
}

func cnameRecords(domain string) {
	cname, _ := net.LookupCNAME(domain)
	if len(cname) < 1 {
		return
	}
	fmt.Println("\n[CNAME Record]", cname)
	analyzeCNAME(cname)
}

func txtRecords(domain string) {
	txtRecords, _ := net.LookupTXT(domain)
	if len(txtRecords) < 1 {
		return
	}
	fmt.Println("\n[TXT Records]")
	for _, txt := range txtRecords {
		fmt.Println(txt)
	}
	analyzeTXT(txtRecords)
}

func spfRecords(domain string) {
	spfRecords, _ := net.LookupTXT(domain)
	if len(spfRecords) < 1 {
		return
	}
	fmt.Println("\n[SPF Records]")
	for _, spf := range spfRecords {
		if strings.HasPrefix(spf, "v=spf1") {
			fmt.Println(spf)
		}
	}
	analyzeSPF(spfRecords)
}

func ptrRecords(domain string) {
	ips, _ := net.LookupIP(domain)
	if len(ips) < 1 {
		return
	}
	ptrPrinted := false
	for _, ip := range ips {
		ptrRecords, _ := net.LookupAddr(ip.String())
		if len(ptrRecords) < 1 {
			continue
		}
		if !ptrPrinted {
			fmt.Println("\n[PTR Records]")
			ptrPrinted = true
		}
		for _, ptr := range ptrRecords {
			fmt.Println(ptr)
		}
	}
}

func reverseLookup(domain string) {
	ips, _ := net.LookupIP(domain)
	if len(ips) < 1 {
		return
	}
	reversePrinted := false
	for _, ip := range ips {
		domains, _ := net.LookupAddr(ip.String())
		if len(domains) < 1 {
			continue
		}
		if !reversePrinted {
			fmt.Println("\n[Reverse Lookup]")
			reversePrinted = true
		}
		for _, domain := range domains {
			fmt.Println(domain)
		}
	}
}

func analyzeSRV(srvAddrs []*net.SRV) {
	fmt.Println("\n[Service Discovery]")
	for _, srv := range srvAddrs {
		fmt.Printf("Service: %s, Port: %d\n", srv.Target, srv.Port)
	}
}

func analyzeTXT(txtRecords []string) {
	fmt.Println("\n[DKIM and DMARC]")
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DKIM1") {
			fmt.Printf("DKIM: %s\n", txt)
		} else if strings.HasPrefix(txt, "v=DMARC1") {
			fmt.Printf("DMARC: %s\n", txt)
		}
	}
}

func analyzeSPF(spfRecords []string) {
	fmt.Println("\n[SPF Allowed IPs and Mechanisms]")
	for _, spf := range spfRecords {
		if strings.HasPrefix(spf, "v=spf1") {
			mechanisms := strings.Split(spf, " ")
			for _, mech := range mechanisms[1:] {
				fmt.Println(strings.TrimPrefix(mech, "ip4:"))
			}
		}
	}
}

func analyzeMX(mxRecords []*net.MX) {
	fmt.Println("\n[Email Service Providers]")
	for _, mx := range mxRecords {
		service := detectService(mx.Host)
		fmt.Printf("%s: %s\n", service, mx.Host)
	}
}

func analyzeNS(nameservers []*net.NS) {
	fmt.Println("\n[DNS Service Providers]")
	for _, ns := range nameservers {
		service := detectService(ns.Host)
		fmt.Printf("%s: %s\n", service, ns.Host)
	}
}

func analyzeCNAME(cname string) {
	fmt.Println("\n[CNAME Subdomain Redirection]")
	fmt.Printf("Redirects to: %s\n", cname)

	fmt.Println("\n[Inferred Services or Platforms]")
	service := detectService(cname)
	fmt.Println(cname + ": " + service)
}

func detectService(domain string) string {
	serviceMap := map[string]string{
		"cloudfront.net":                  "Amazon CloudFront CDN",
		"akamai.net":                      "Akamai CDN",
		"fastly.net":                      "Fastly CDN",
		"cdn.cloudflare.net":              "Cloudflare CDN",
		"domains.tumblr.com":              "Tumblr",
		"zendesk.com":                     "Zendesk",
		"bitly.com":                       "Bitly",
		"google":                          "Google Workspace",
		"outlook":                         "Microsoft 365",
		"office365":                       "Microsoft 365",
		"awsdns":                          "AWS Route 53",
		"cloudflare":                      "Cloudflare",
		"mimecast":                        "Mimecast",
		"googledomains":                   "Google Cloud DNS",
		"pages.github.io":                 "GitHub Pages",
		"sharepoint.com":                  "Microsoft SharePoint",
		"ultradns":                        "UltraDNS",
		"dynect.net":                      "Dynect",
		"salesforce.com":                  "Salesforce",
		"googleusercontent.com":           "Google Cloud Storage",
		"c.storage.googleapis.com":        "Google Cloud Storage (CNAME)",
		"s3.amazonaws.com":                "Amazon S3",
		"s3-website":                      "Amazon S3 Static Website",
		"appspot.com":                     "Google App Engine",
		"azurewebsites.net":               "Microsoft Azure Web Apps",
		"cloudapp.net":                    "Microsoft Azure Cloud Services",
		"trafficmanager.net":              "Microsoft Azure Traffic Manager",
		"cdn.shopify.com":                 "Shopify CDN",
		"wixdns.net":                      "Wix",
		"squarespace.com":                 "Squarespace",
		"weebly.com":                      "Weebly",
		"godaddy.com":                     "GoDaddy",
		"bluehost.com":                    "Bluehost",
		"hostgator.com":                   "HostGator",
		"cloudfront":                      "Cloudfront",
		"dreamhost.com":                   "DreamHost",
		"inmotionhosting.com":             "InMotion Hosting",
		"siteground.com":                  "SiteGround",
		"wpengine.com":                    "WP Engine",
		"digitalocean.com":                "DigitalOcean",
		"linode.com":                      "Linode",
		"herokuapp.com":                   "Heroku",
		"aws.amazon.com/lambda":           "AWS Lambda",
		"aws.amazon.com/dynamodb":         "AWS DynamoDB",
		"aws.amazon.com/rds":              "AWS RDS",
		"aws.amazon.com/ec2":              "AWS EC2",
		"aws.amazon.com/elasticbeanstalk": "AWS Elastic Beanstalk",
		"aws.amazon.com/cloudformation":   "AWS CloudFormation",
		"aws.amazon.com/elasticache":      "AWS ElastiCache",
		"aws.amazon.com/cloudfront":       "AWS CloudFront",
		"aws.amazon.com/sqs":              "AWS SQS",
		"aws.amazon.com/sns":              "AWS SNS",
		"aws.amazon.com/kinesis":          "AWS Kinesis",
		"aws.amazon.com/glacier":          "AWS Glacier",
		"aws.amazon.com/s3":               "AWS S3 (non-website)",
		"aws.amazon.com/appsync":          "AWS AppSync",
		"aws.amazon.com/amplify":          "AWS Amplify",
		"aws.amazon.com/cognito":          "AWS Cognito",
		"aws.amazon.com/polly":            "AWS Polly",
		"aws.amazon.com/lex":              "AWS Lex",
		"aws.amazon.com/rekognition":      "AWS Rekognition",
		"aws.amazon.com/transcribe":       "AWS Transcribe",
		"aws.amazon.com/translate":        "AWS Translate",
		"aws.amazon.com/comprehend":       "AWS Comprehend",
		"aws.amazon.com/kendra":           "AWS Kendra",
		"aws.amazon.com/textract":         "AWS Textract",
		"aws.amazon.com/personalize":      "AWS Personalize",
		"aws.amazon.com/sagemaker":        "AWS SageMaker",
		"aws.amazon.com/glue":             "AWS Glue",
		"aws.amazon.com/lake-formation":   "AWS Lake Formation",
		"aws.amazon.com/redshift":         "AWS Redshift",
		"aws.amazon.com/athena":           "AWS Athena",
		"aws.amazon.com/quicksight":       "AWS QuickSight",
		"aws.amazon.com":                  "Amazon Web Services",
		"azure.microsoft.com":             "Microsoft Azure",
		"gcp.google.com":                  "Google Cloud Platform",
		"cloud.google.com":                "Google Cloud Platform",
		"appharbor.com":                   "AppHarbor",
		"cdn.akamaized.net":               "Akamai CDN",
		"cdn.jsdelivr.net":                "jsDelivr CDN",
		"stackpath.bootstrapcdn.com":      "Bootstrap CDN",
		"cdnjs.cloudflare.com":            "cdnjs CDN",
		"maxcdn.bootstrapcdn.com":         "Bootstrap CDN",
		"fonts.gstatic.com":               "Google Fonts",
		"themes.googleusercontent.com":    "Google Sites",
		"docs.google.com":                 "Google Docs",
		"sheets.google.com":               "Google Sheets",
		"slides.google.com":               "Google Slides",
		"sites.google.com":                "Google Sites",
		"storage.googleapis.com":          "Google Cloud Storage",
		"firebaseio.com":                  "Firebase Realtime Database",
		"firebaseapp.com":                 "Firebase Hosting",
		"console.aws.amazon.com":          "Amazon Web Services Console",
		"console.cloud.google.com":        "Google Cloud Console",
		"console.firebase.google.com":     "Firebase Console",
		"dashboard.heroku.com":            "Heroku Dashboard",
		"api.heroku.com":                  "Heroku Platform API",
		"dashboard.ngrok.com":             "ngrok Dashboard",
		"statuspage.io":                   "Statuspage",
		"git-scm.com":                     "Git",
		"subversion.apache.org":           "Subversion",
		"mercurial-scm.org":               "Mercurial",
		"unity3d.com":                     "Unity",
		"unrealengine.com":                "Unreal Engine",
		"blender.org":                     "Blender",
		"autodesk.com":                    "Autodesk",
		"openshift.com":                   "OpenShift",
		"jelastic.com":                    "Jelastic",
		"bitbucket.org":                   "Bitbucket",
		"gitlab.com":                      "GitLab",
		"travis-ci.com":                   "Travis CI",
		"circleci.com":                    "CircleCI",
		"jenkins.io":                      "Jenkins",
		"teamcity.com":                    "TeamCity",
		"codeship.com":                    "Codeship",
		"docker.com":                      "Docker",
		"kubernetes.io":                   "Kubernetes",
		"rabbitmq.com":                    "RabbitMQ",
		"redis.io":                        "Redis",
		"postgresql.org":                  "PostgreSQL",
		"mysql.com":                       "MySQL",
		"mongodb.com":                     "MongoDB",
		"elasticsearch.org":               "Elasticsearch",
		"prometheus.io":                   "Prometheus",
		"grafana.com":                     "Grafana",
		"kibana.org":                      "Kibana",
		"logstash.net":                    "Logstash",
		"splunk.com":                      "Splunk",
		"sumologic.com":                   "Sumo Logic",
		"newrelic.com":                    "New Relic",
		"datadoghq.com":                   "Datadog",
		"pingdom.com":                     "Pingdom",
		"uptimerobot.com":                 "UptimeRobot",
		"cloudinary.com":                  "Cloudinary",
		"imgix.com":                       "Imgix",
		"twilio.com":                      "Twilio",
		"nexmo.com":                       "Nexmo",
		"sendgrid.com":                    "SendGrid",
		"mailchimp.com":                   "Mailchimp",
		"aws.amazon.com/ses":              "Amazon SES",
		"postmarkapp.com":                 "Postmark",
		"stripe.com":                      "Stripe",
		"paypal.com":                      "PayPal",
		"braintree.com":                   "Braintree",
		"squareup.com":                    "Square",
		"coinbase.com":                    "Coinbase",
		"blockchain.info":                 "Blockchain",
		"auth0.com":                       "Auth0",
		"okta.com":                        "Okta",
		"stormpath.com":                   "Stormpath",
		"firebase.google.com":             "Firebase",
		"onesignal.com":                   "OneSignal",
		"pusher.com":                      "Pusher",
	}

	for key, value := range serviceMap {
		if strings.Contains(domain, key) {
			return value
		}
	}

	return "Other"
}

type Geolocation struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

func ipGeolocation(ip net.IP) {
	resp, err := http.Get(fmt.Sprintf("https://ipinfo.io/%s/json", ip.String()))
	if err != nil {
		fmt.Println("Error fetching geolocation:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading geolocation response:", err)
		return
	}

	var geo Geolocation
	err = json.Unmarshal(body, &geo)
	if err != nil {
		fmt.Println("Error decoding geolocation JSON:", err)
		return
	}

	fmt.Printf("-  Country: %s, Region: %s, City: %s\n", geo.Country, geo.Region, geo.City)
}

func asnLookup(ip net.IP) {
	asnIP := fmt.Sprintf("%s.origin.asn.cymru.com", reverseIP(ip.String()))
	txtRecords, err := net.LookupTXT(asnIP)
	if err != nil {
		log.Println("Error in ASN lookup:", err)
		return
	}

	if len(txtRecords) > 0 {
		fields := strings.Split(txtRecords[0], " | ")
		if len(fields) >= 6 {
			asn := fields[0]
			ipRange := fields[1]
			country := fields[2]
			registry := fields[3]
			allocated := fields[4]
			asName := fields[5]

			fmt.Printf("ASN: %s, Name: %s, AllocatedAt: %s, Country: %s, Range: %s, Registry: %s\n",
				asn, asName, allocated, country, ipRange, registry)
		}
	}
}

func checkBlacklist(ip net.IP) {
	blacklists := []string{
		"zen.spamhaus.org",
		"bl.score.senderscore.com",
		"psbl.surriel.com",
	}

	for _, bl := range blacklists {
		lookup := fmt.Sprintf("%s.%s", reverseIP(ip.String()), bl)
		_, err := net.LookupHost(lookup)
		if err == nil {
			fmt.Printf("-  IP %s is listed on blacklist: %s\n", ip.String(), bl)
		}
	}
}

func reverseIP(ip string) string {
	octets := strings.Split(ip, ".")
	reversed := []string{}

	for i := len(octets) - 1; i >= 0; i-- {
		reversed = append(reversed, octets[i])
	}

	return strings.Join(reversed, ".")
}
