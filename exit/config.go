package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path"
	"time"

	"github.com/icydoge/MoatCailin/crypt"
)

const serverIdentifierMinLength = 4

// Raw configurations for JSON parsing.
type rawEntryServer struct {
	ServerIdentifier string `json:"identifier"`
	ServerPubKey     string `json:"pubkey"`
}

type rawDNSServer struct {
	DNSIP       string `json:"ip"`
	DNSPriority int    `json:"priority"`
}

type rawConfig struct {
	ExitName       string           `json:"exit_name"`
	ExitIdentifier string           `json:"exit_identifier"`
	ConfigRoot     string           `json:"config_root"`
	TimeOut        time.Duration    `json:"timeout"`
	PrivateKeyFile string           `json:"encrypted_private_key"`
	EntryServers   []rawEntryServer `json:"entry_servers"`
	// DNSServers     []rawDNSServer   `json:"dns_servers"`
}

// EntryServer defines a trusted entry server by this exit.
type EntryServer struct {
	ServerIdentifier string
	ServerPubKey     *crypt.RSAPublicKey
}

// DNSServer defines an external DNS server used for relayed
// hostname resolution.
// type DNSServer struct {
// 	DNSIP       net.IP
// 	DNSPriority int
// }

// var defaultDNSServers = []DNSServer{
// 	DNSServer{DNSIP: net.ParseIP("8.8.8.8"), DNSPriority: 2},
// 	DNSServer{DNSIP: net.ParseIP("8.8.4.4"), DNSPriority: 1},
// }

// Config defines the configurations of this exit.
type Config struct {
	ExitName       string
	ExitIdentifier string
	TimeOut        time.Duration
	EntryServers   []EntryServer
	// DNSServers     []DNSServer
	ExitPrivateKey *crypt.RSAPrivateKey
}

// ReadConfig parses the configuration file at proscribed location
// and returns a pointer to the config parsed, or nil if config
// invalid or does not exist.
func ReadConfig(configJSONPath string) *Config {
	raw, err := ioutil.ReadFile(configJSONPath)
	if err != nil {
		return nil
	}

	var config rawConfig
	err = json.Unmarshal(raw, &config)
	if err != nil {
		return nil
	}

	if config.TimeOut < 1 {
		log.Println("Setting timeout to default (10).")
		config.TimeOut = 10
	}

	// Process the config.
	var processedConfig Config
	processedConfig.TimeOut = config.TimeOut
	processedConfig.ExitName = config.ExitName

	// Process private key.
	if len(config.ExitIdentifier) < serverIdentifierMinLength {
		panic("Invalid exit identifier length.")
	}
	processedConfig.ExitIdentifier = config.ExitIdentifier

	processedConfig.ExitPrivateKey, err = crypt.ReadPrivateKey(path.Join(config.ConfigRoot, config.PrivateKeyFile))
	if err != nil {
		log.Printf("Private key error: %v\n", err)
		panic("Error reading exit private key.")
	}

	// // Process DNS servers.
	// var processedDNS []DNSServer
	// for _, s := range config.DNSServers {
	// 	ip := net.ParseIP(s.DNSIP)
	// 	if ip == nil {
	// 		log.Printf("Invalid DNS IP: %s\n", s.DNSIP)
	// 		continue
	// 	}
	// 	processedDNS = append(processedDNS, DNSServer{DNSIP: ip, DNSPriority: s.DNSPriority})
	// }
	// processedConfig.DNSServers = processedDNS

	// // Use default DNS servers if required.
	// if len(processedConfig.DNSServers) == 0 {
	// 	processedConfig.DNSServers = defaultDNSServers
	// 	log.Println("No valid DNS server configured, using defaults.")
	// }

	// sort.Slice(processedConfig.DNSServers,
	// 	func(i, j int) bool {
	// 		return processedConfig.DNSServers[i].DNSPriority > processedConfig.DNSServers[j].DNSPriority
	// 	},
	// )

	// Process entry servers.
	// Server name
	var processedEntries []EntryServer
	var seenIdentifiers []string
	for _, s := range config.EntryServers {

		if len(s.ServerIdentifier) < serverIdentifierMinLength {
			log.Printf("Invalid entry identifier length: %s\n", s.ServerIdentifier)
			continue
		}

		idSeen := false
		for _, v := range seenIdentifiers {
			if v == s.ServerIdentifier {
				idSeen = true
				break
			}
		}
		if idSeen {
			log.Printf("Duplicate server identifier: %s\n", s.ServerIdentifier)
		} else {
			seenIdentifiers = append(seenIdentifiers, s.ServerIdentifier)
		}

		pubkey, err := crypt.ReadPublicKey(path.Join(config.ConfigRoot, s.ServerPubKey))
		if err != nil {
			log.Printf("Public key error: %v\n", err)
			panic("Error reading exit private key.")
		}

		processedEntries = append(processedEntries, EntryServer{
			ServerIdentifier: s.ServerIdentifier,
			ServerPubKey:     pubkey,
		})
	}
	processedConfig.EntryServers = processedEntries

	if len(processedConfig.EntryServers) == 0 {
		panic("No entry server supplied in config, MoatCailin cannot run.")
	}

	return &processedConfig
}
