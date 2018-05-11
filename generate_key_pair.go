package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/icydoge/MoatCailin/utils"
)

// Borrowed from https://stackoverflow.com/a/35240286/5693062
func testValidPath(fp string) bool {
	// Check if file already exists
	if _, err := os.Stat(fp); err == nil {
		return true
	}

	// Attempt to create it
	var d []byte
	if err := ioutil.WriteFile(fp, d, 0644); err == nil {
		os.Remove(fp) // And delete it
		return true
	}

	return false
}

func main() {
	fmt.Println(`This program will generate an SHA key pair for a MoatCailin entry or exit server,
responsible for traffic encryption and authentication between entry and exit servers.`)

	var exportPath = flag.String("path", "/usr/local/etc/moatcailin/", "Path to directory storing the generated keypair.")
	var exportName = flag.String("name", "MoatCailinNode", "Name prefix for the private and public key files.")
	flag.Parse()

	if !testValidPath(*exportPath) {
		fmt.Println("The target path specified is not valid.")
		os.Exit(1)
	}

	if len(*exportName) == 0 {
		fmt.Println("The key file name cannot be empty.")
		os.Exit(1)
	}

	fmt.Println("Generating the private and public keys...")
	private, public := utils.GenRSAKeyPair()
	if private == nil || public == nil {
		fmt.Println("Runtime error was encountered while generating the key pair.")
		os.Exit(1)
	}

	privateOutPath := path.Join(*exportPath, strings.Join([]string{*exportName, "_PRIVATE.pem"}, ""))
	publicOutPath := path.Join(*exportPath, strings.Join([]string{*exportName, "_PUBLIC.pem"}, ""))
	fmt.Println("Saving the private key...")
	err1 := private.Save(privateOutPath)
	fmt.Println("Saving the public key...")
	err2 := public.Save(publicOutPath)

	if err1 != nil {
		fmt.Printf("Error encountered in saving the private key to %v .\n", privateOutPath)
	} else {
		fmt.Printf("Successfully saved the private key to %v .\n", privateOutPath)
	}

	if err2 != nil {
		fmt.Printf("Error encountered in saving the public key to %v .\n", publicOutPath)
	} else {
		fmt.Printf("Successfully saved the public key to %v .\n", publicOutPath)
	}

}
