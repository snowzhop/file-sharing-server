package main

import (
	"fmt"

	"./config"
	"./tcp"
)

func main() {
	fmt.Println("----MAIN")
	configuration := config.GetServerConfig()

	fmt.Printf("Address: %s\n", configuration.Address())
	fmt.Printf("Port: %v\n", configuration.Port())
	fmt.Printf("Session name: %v\n", configuration.SessionName())
	fmt.Printf("Cipher: %t\n", configuration.Cipher())
	fmt.Printf("Working directory: %v\n", configuration.WorkingDirectory())

	tcp.StartServer(configuration)
}
