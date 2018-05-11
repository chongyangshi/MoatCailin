package main

import (
	"flag"
	"fmt"
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
		fmt.Printf("ID %s; \n", v.ServerIdentifier)
	}
	fmt.Printf("\n")
}

func main() {
	var configPath = flag.String("config", "~/mc_exit.json", "path to the MoatCailin exit server configuration file (default: ~/mc_exit.json).")
	flag.Parse()

	printConfig(ReadConfig(*configPath))
}
