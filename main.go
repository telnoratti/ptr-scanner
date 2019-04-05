package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"go.uber.org/ratelimit"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
)

type queryEngine struct {
	limiter     ratelimit.Limiter
	nameServers []string
	client      dns.Client
	ip          net.IP
	subnet      net.IPNet
	output      chan *dns.PTR
	waitGroup   *sync.WaitGroup
	attempts    int
}

const (
	IPv4 = iota
	IPv6 = iota
)

var opts struct {
	Verbose  []bool   `short:"v" long:"verbose" description:"Show verbose debug information"`
	Rate     int      `short:"r" default:"600" long:"rate" description:"Queries per second"`
	Servers  []string `short:"s" long:"server" description:"Nameserver to query"`
	Attempts int      `short:"a" long:"attempts" default:"5" description:"Number of attempts if timeout"`
}

func main() {
	args, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}
	// TODO this could be a lot better
	for i, server := range opts.Servers {
		if strings.Index(server, ":") == -1 {
			opts.Servers[i] = server + ":53"
		} else {
			opts.Servers[i] = "[" + server + "]" + ":53"
		}
	}
	var engines []*queryEngine = make([]*queryEngine, len(args))
	for i, prefix := range args {
		engines[i] = new(queryEngine)
		engines[i].initEngine(prefix)
		queryString, err := subnetToQuery(&engines[i].subnet)
		if err != nil {
			panic(err)
		}
		engines[i].scanNextDivision(queryString)
		go printResults(engines[i].output)
	}

	for _, engine := range engines {
		engine.waitGroup.Wait()
	}
	//go func() {
	//	for {
	//		time.Sleep(1 * time.Second)
	//		log.Println(engine.waitGroup)
	//	}
	//}()
}

func printResults(input chan *dns.PTR) {
	for {
		fmt.Println(<-input)
	}
}

func subnetToQuery(subnet *net.IPNet) (string, error) {
	var end string
	var chunks []string
	mask, _ := subnet.Mask.Size()
	if subnet.IP.To4() != nil {
		end = ".in-addr.arpa."
		if mask%8 != 0 {
			return "", fmt.Errorf("Subnet must be at the byte level for IPv4\n")
		}
		chunks = make([]string, 4)
		for index, element := range subnet.IP {
			chunks[len(chunks)-index-1] = strconv.FormatUint(uint64(element), 10)
		}
		chunks = chunks[len(chunks)-mask/8 : len(chunks)]
	} else {
		end = ".ip6.arpa."
		if mask%4 != 0 {
			return "", fmt.Errorf("Subnet must be at the nibble level for IPv6\n")
		}
		chunks = make([]string, 32)
		for index, element := range subnet.IP {
			chunks[len(chunks)-2*index-1] = strconv.FormatUint(uint64((element&0xF0)>>4), 16)
			chunks[len(chunks)-2*index-2] = strconv.FormatUint(uint64(element&0x0F), 16)
		}
		// Now we shorten it to the appropriate mask
		chunks = chunks[len(chunks)-mask/4 : len(chunks)]
	}
	return strings.Join(chunks, ".") + end, nil
}

/*func ptrToIP(ptr string) string {
	var output *strings.Builder = new(strings.Builder)
	if ptr[len(ptr)-10:] == ".ip6.arpa." {
		//IPv6
	} else { //IPv4
	}
}*/

func (engine *queryEngine) initEngine(prefix string) {
	// parse prefix
	ip, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		panic(err)
	}
	engine.ip = ip
	engine.subnet = *subnet

	engine.limiter = ratelimit.New(opts.Rate)
	engine.nameServers = opts.Servers

	engine.output = make(chan *dns.PTR, 10)
	engine.attempts = opts.Attempts

	engine.waitGroup = new(sync.WaitGroup)
	engine.waitGroup.Add(1)
}

func (engine *queryEngine) selectServer() string {
	return engine.nameServers[rand.Intn(len(engine.nameServers))]
}

func (engine *queryEngine) scanNextDivision(query string) {
	var err error
	engine.limiter.Take()
	message := new(dns.Msg)
	message.SetQuestion(query, dns.TypePTR)
	message.RecursionDesired = true

	var msg *dns.Msg
	// TODO randomize nameserver
	for i := 0; i < engine.attempts; i++ {
		msg, err = dns.Exchange(message, engine.selectServer())
		if err == nil {
			break
		}
	}
	if err != nil {
		panic(err)
	}
	if msg.Rcode == dns.RcodeSuccess {
		// Did we find something here?
		if len(msg.Answer) > 0 {
			for _, answer := range msg.Answer {
				switch ptrAnswer := answer.(type) {
				case *dns.PTR:
					engine.output <- ptrAnswer
				}
			}
			// Now leave
		} else {
			//log.Println("Querying subdivisions")

			// Nothing here, but there is a record further down
			if engine.subnet.IP.To4() != nil {
				engine.waitGroup.Add(256)
				// Use 0-255
				for i := 0; i <= 255; i++ {
					go engine.scanNextDivision(strconv.FormatUint(uint64(i), 10) + "." + query)
				}
			} else {
				engine.waitGroup.Add(16)
				// use 0-f
				for i := 0; i <= 0xf; i++ {
					go engine.scanNextDivision(strconv.FormatUint(uint64(i), 16) + "." + query)
				}
			}
		}
	} else if msg.Rcode == dns.RcodeNameError {
		// Nothing further down this path, abort
	} else {
		// This was not expected
		log.Println(msg.String())
	}
	engine.waitGroup.Done()
}
