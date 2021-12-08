package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Note: a longer timeout is preferable, it works better with the DNS resolving process
//       the overall resolving will be faster (which is counter intuitive but tested to be true)
const (
	TIMEOUT    time.Duration = 10 //seconds
	CONCURRENT uint          = 450
	EDNS0SIZE  uint16        = 1440
)

// Fastest results achieved by using Google and Cloudflare only(!!!)
var resolvers []string = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	//"9.9.9.9:53", // Quad9
	//"94.140.14.14:53",   // Adguard
	//"208.67.222.222:53", // OpenDNS
	//"64.6.64.6:53", // Verisign
}

var verbose = 5

var has_dmarc int = 0
var has_valid_dmarc int = 0
var has_p_is_none int = 0
var has_p_is_quar int = 0
var has_p_is_reje int = 0
var count_domains int = 0

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Exactly one argument expected. (File with list of domain names.)")
	}
	// start time keeping
	start := time.Now()
	time.Sleep(1 * time.Millisecond) // wait 1ms, so we do not run into a divide by zero later

	// this is the index of the next resolver to use
	resolver := 0

	// syncing of go routines
	var wg sync.WaitGroup
	var threads = make(chan string, CONCURRENT)

	// Open the file. One domain per line
	f, _ := os.Open(os.Args[1])
	scanner := bufio.NewScanner(f)

	// loop over all lines/domains
	for scanner.Scan() {
		line := scanner.Text()
		count_domains++

		// resolving is done in a go routine
		wg.Add(1)
		threads <- "x"
		go getDMarc(line, &wg, threads, resolvers[resolver])

		// select next resolver
		resolver++
		if resolver == len(resolvers) {
			resolver = 0
		}

		// progress output
		elapsed := time.Now().Sub(start)
		log.Printf("%d domains, %d (%0.2f%%) DMarc, %d (%0.2f%%) DMarc valid, %d (%0.2f%%) p=none, %d (%0.2f%%) p=quarantine, %d (%0.2f%%) p=reject, %s, %d domains/s",
			count_domains,
			has_dmarc,
			float32(has_dmarc)/float32(count_domains)*100,
			has_valid_dmarc,
			float32(has_valid_dmarc)/float32(count_domains)*100,
			has_p_is_none,
			float32(has_p_is_none)/float32(count_domains)*100,
			has_p_is_quar,
			float32(has_p_is_quar)/float32(count_domains)*100,
			has_p_is_reje,
			float32(has_p_is_reje)/float32(count_domains)*100,
			elapsed.String(),
			int64(count_domains)*1000/elapsed.Milliseconds())
	}

	// sync with all routines
	wg.Wait()
	close(threads)

	// final result
	elapsed := time.Now().Sub(start)
	log.Printf("FINAL %d domains, %d (%0.2f%%) DMarc, %d (%0.2f%%) DMarc valid, %d (%0.2f%%) p=none, %d (%0.2f%%) p=quarantine, %d (%0.2f%%) p=reject, %s, %d domains/s",
		count_domains,
		has_dmarc,
		float32(has_dmarc)/float32(count_domains)*100,
		has_valid_dmarc,
		float32(has_valid_dmarc)/float32(count_domains)*100,
		has_p_is_none,
		float32(has_p_is_none)/float32(count_domains)*100,
		has_p_is_quar,
		float32(has_p_is_quar)/float32(count_domains)*100,
		has_p_is_reje,
		float32(has_p_is_reje)/float32(count_domains)*100,
		elapsed.String(),
		int64(count_domains)*1000/elapsed.Milliseconds())

}

// async resolv dmarc records
func getDMarc(domain string, wg *sync.WaitGroup, threads <-chan string, server string) {
	// cleanup when we are done
	defer wg.Done()

	// get data
	txt := resolve("_dmarc."+dns.Fqdn(domain), dns.TypeTXT, server, 0)
	_ = <-threads // some other routine can now start to resolve

	// an error occurred, nothing to count
	if txt == nil {
		return
	}

	// a domain could have several txt records, some being dmarc records some
	// so we need to check each record for being a dmarc record
	// but also make sure we do not count any domain double
	found := 0
	valid := 0
	pisnone := 0
	pisquar := 0
	pisreje := 0
	for _, rr := range txt.Answer {
		if rr.Header().Rrtype != dns.TypeTXT {
			continue
		}
		found++
		if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), "v=DMARC1;") == 0 {
			valid++
			if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), " p=none") >= 0 {
				pisnone++
			} else {
				if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), ";p=none") >= 0 {
					pisnone++
				}
			}
			if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), " p=quarantine") >= 0 {
				pisquar++
			} else {
				if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), ";p=quarantine") >= 0 {
					pisquar++
				}
			}
			if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), " p=reject") >= 0 {
				pisreje++
			} else {
				if strings.Index(strings.Join(rr.(*dns.TXT).Txt, ""), ";p=reject") >= 0 {
					pisreje++
				}
			}
		}
	}

	// now counting
	//NOTE: int variables can be accessed from go routines without syncing
	if found > 0 {
		has_dmarc++
	}
	if valid > 0 {
		has_valid_dmarc++
	}
	if pisnone > 0 {
		has_p_is_none++
	}
	if pisquar > 0 {
		has_p_is_quar++
	}
	if pisreje > 0 {
		has_p_is_reje++
	}
}

// this is done as global variable to speed up the resolving process
var client *dns.Client

func init() {
	// Setting up resolver
	client = new(dns.Client)
	client.ReadTimeout = TIMEOUT * time.Second
}

// resolv will send a query and return the result
func resolve(qname string, qtype uint16, server string, count uint) *dns.Msg {

	// max three retries
	if count > 3 {
		return nil
	}

	// Setting up query
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.SetEdns0(EDNS0SIZE, false)
	query.IsEdns0().SetDo()
	query.RecursionDesired = true

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		log.Printf("%-30s: Error resolving %s (server %s)\n", qname, err, server)
		return resolve(qname, qtype, server, count+1)
	}
	if r == nil {
		log.Printf("%-30s: No answer (Server %s)\n", qname, server)
		return resolve(qname, qtype, server, count+1)
	}

	return r
}
