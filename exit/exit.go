package exit

import (
	"flag"
	"fmt"
	"os/user"
	"path"
	"strings"
)

func printConfig(config *Config) {
	if config == nil {
		fmt.Println("Config invalid.")
		return
	}
	fmt.Printf("MoatCailin exit server: %s (%s). \n", config.ExitName, config.ExitIdentifier)
	fmt.Printf("Server timeout: %d seconds.\n", config.TimeOut)
	// fmt.Println("DNS Resolvers:")
	// for _, v := range config.DNSServers {
	// 	fmt.Printf("%s (priority: %d)\n", v.DNSIP.String(), v.DNSPriority)
	// }
	fmt.Printf("\nEntry Servers:\n")
	for _, v := range config.EntryServers {
		fmt.Printf("ID %s (key %v) \n", v.ServerIdentifier, v.ServerPubKey.Fingerprint())
	}
	fmt.Printf("\n")
}

func main() {
	var configPath = flag.String("config", "~/.config/mc_exit.json", "path to the MoatCailin exit server configuration file (default: ~/mc_exit.json).")
	flag.Parse()

	if strings.HasPrefix(*configPath, "~") {
		u, _ := user.Current()
		*configPath = path.Join(u.HomeDir, string(*configPath)[1:])
	}

	printConfig(ReadConfig(*configPath))
}
