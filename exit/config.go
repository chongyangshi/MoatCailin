package exit

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path"
	"time"

	"github.com/chongyangshi/MoatCailin/crypt"
)

// Raw configurations for JSON parsing.
type rawEntryServer struct {
	ServerPubKey string `json:"pubkey"`
}

type rawDNSServer struct {
	DNSIP       string `json:"ip"`
	DNSPriority int    `json:"priority"`
}

type rawConfig struct {
	ExitName       string           `json:"exit_name"`
	ConfigRoot     string           `json:"config_root"`
	TimeOut        time.Duration    `json:"timeout"`
	PrivateKeyFile string           `json:"encrypted_private_key"`
	PublicKeyFile  string           `json:"public_key"`
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
	processedConfig.ExitPrivateKey, err = crypt.ReadPrivateKey(path.Join(config.ConfigRoot, config.PrivateKeyFile))
	if err != nil {
		log.Printf("Private key error: %v\n", err)
		panic("Error reading exit private key.")
	}
	exitPublicKey, err := crypt.ReadPublicKey(path.Join(config.ConfigRoot, config.PublicKeyFile))
	if err != nil {
		log.Printf("Public key error: %v\n", err)
		panic("Error reading exit public key.")
	}

	// The server identifier is the SHA256 hash of its public key bytes.
	processedConfig.ExitIdentifier = exitPublicKey.Identifier()

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

		pubkey, err := crypt.ReadPublicKey(path.Join(config.ConfigRoot, s.ServerPubKey))
		if err != nil {
			log.Printf("Public key error: %v\n", err)
			panic("Error reading exit private key.")
		}

		idSeen := false
		for _, v := range seenIdentifiers {
			if v == pubkey.Identifier() {
				idSeen = true
				break
			}
		}
		if idSeen {
			log.Printf("Duplicate server identifier: %s\n", pubkey.Identifier())
		} else {
			seenIdentifiers = append(seenIdentifiers, pubkey.Identifier())
		}

		processedEntries = append(processedEntries, EntryServer{
			ServerIdentifier: pubkey.Identifier(),
			ServerPubKey:     pubkey,
		})
	}
	processedConfig.EntryServers = processedEntries

	if len(processedConfig.EntryServers) == 0 {
		panic("No entry server supplied in config, MoatCailin cannot run.")
	}

	return &processedConfig
}
