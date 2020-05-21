package config

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func init() {

	var (
		encryptFlag    bool
		addrFlag       string
		nameFlag       string
		passwordFlag   string
		workingDirFlag string
		portFlag       port
	)

	/* GET DEFAULT WORKING DIR */
	var err error
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\tInit error: %v\n", err)
		os.Exit(1)
	}
	defaultWorkingDir := homeDir + "/" + defaultWorkingDirName

	flag.BoolVar(&encryptFlag, "e", false, "encrypt all files")
	flag.StringVar(&addrFlag, "addr", "", "set server IP-address")
	flag.StringVar(&workingDirFlag, "work", defaultWorkingDir, "set working dir for session")
	flag.StringVar(&nameFlag, "name", "", "set session name")
	flag.StringVar(&passwordFlag, "pass", "", "set root password")
	flag.Var(&portFlag, "port", "set server port(0-"+strconv.Itoa(maxPort)+")")

	flag.Parse()

	input := bufio.NewScanner(os.Stdin)

	/* SESSION NAME */
	if len(nameFlag) == 0 {
		fmt.Print("Set session name > ")
		if input.Scan() {
			nameFlag = input.Text()
		}
	}

	/* PASSWORD */
	if len(passwordFlag) == 0 {
		fmt.Print("Set root password > ")
		tmpPassSlice, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\tCan't read password.\n\tError: %v\n", err)
			os.Exit(1)
		}
		passwordFlag = string(tmpPassSlice)
		fmt.Println()
	}

	/* MAIN CONFIG DIR */
	configDir, err = os.UserConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\tInit error: %v\n", err)
		os.Exit(1)
	}

	configDir += "/" + projectName
	sessionDir := configDir + "/" + nameFlag

	/* If main config directory doesn't exist */
	if _, err = os.Stat(configDir); os.IsNotExist(err) {
		err = os.Mkdir(configDir, 0777)
		if err != nil {
			fmt.Fprintln(os.Stderr, "\tError: Can't create config directory.\nError: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("Main config directory created")
	} else {
		fmt.Println("Main config directory already exists")
	}

	/* IP-ADDRESS CHECK */
	var tmpAddr net.IP = nil
	if len(addrFlag) != 0 {
		tmpAddr = net.ParseIP(addrFlag)
		if tmpAddr == nil {
			fmt.Fprintf(os.Stderr, "\tError: Wrong IP-address (%s).\n", addrFlag)
			os.Exit(1)
		}
	}

	/* If config for this 'name' exists */
	if _, err = os.Stat(sessionDir); !os.IsNotExist(err) {
		fmt.Printf("Session '%s' already exists\n", nameFlag)

		/* Password checking */
		if !isRootPasswordCorrect(nameFlag, passwordFlag) {
			fmt.Fprintln(os.Stderr, "\tError: Wrong root password.")
			os.Exit(1)
		}

		rewriteConfig := false

		err = serverConfig.unmarshalFromFileJSON(nameFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\tError: Can't get config from file %s_config.json\n", nameFlag)
			fmt.Fprintf(os.Stderr, "\tExtended description: %v\n", err.Error())
			os.Exit(1)
		}

		if serverConfig.doEncrypt != encryptFlag {
			fmt.Println("Encryption settings are already set.")
		}

		/* Replace port */
		if portFlag != 0 {
			serverConfig.portNumber = portFlag
			rewriteConfig = true
		}

		/* Replace address */
		if tmpAddr != nil {
			serverConfig.IPAddr = tmpAddr
			rewriteConfig = true
		}

		if rewriteConfig {
			serverConfig.marshalAndSaveJSON()
		}

		return
	}

	/* IP-ADDRESS */
	if tmpAddr == nil {
		fmt.Print("Ser server IP-address > ")
		if input.Scan() {
			addrFlag = input.Text()
			tmpAddr = net.ParseIP(addrFlag)
			if tmpAddr == nil {
				fmt.Fprintf(os.Stderr, "\tError: Wrong IP-address (%s).\n", addrFlag)
				os.Exit(1)
			}
		}
	}

	/* SERVER PORT */
	if portFlag == 0 {
		fmt.Printf("Set server port(0-%d) > ", maxPort)
		if input.Scan() {
			tmpPort, err := strconv.ParseUint(input.Text(), 10, 16)
			if err != nil {
				e := err.(*strconv.NumError)
				fmt.Fprintf(os.Stderr, "\tError: Wrong port number.\n\tDetails: %v.\n", e.Err)
				os.Exit(1)
			}
			portFlag = port(tmpPort)
		}
	}

	workingDirFlag = homeDir + "/" + workingDirFlag
	/* MAIN CONFIG INFO */
	serverConfig.IPAddr = tmpAddr
	serverConfig.portNumber = portFlag
	serverConfig.sessionName = nameFlag
	serverConfig.doEncrypt = encryptFlag
	serverConfig.workingDirectory = workingDirFlag

	createBaseFiles(nameFlag, passwordFlag, workingDirFlag)

}

func isRootPasswordCorrect(sessionName, password string) bool {
	file, err := os.Open(configDir + "/" + sessionName + "/" + sessionName + passwordFileSuffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\rError: Can't open users' password file.\n\tExtended description: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	fileReader := bufio.NewReader(file)
	rootPass, err := fileReader.ReadSlice('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "\tError: Can't read root password.\n\tExtended description: %v\n", err)
		os.Exit(1)
	}

	colonIndex := bytes.IndexByte(rootPass, ':')
	if colonIndex == -1 {
		fmt.Fprintf(os.Stderr, "\tError: Can't read root password. Wrong file or data.\n")
		os.Exit(1)
	}

	realPassHash := rootPass[colonIndex+1 : len(rootPass)-1]
	passForVerifying := sha256.Sum256([]byte(password))

	for i, b := range realPassHash {
		if b != passForVerifying[i] {
			return false
		}
	}

	return true
}

func createBaseFiles(sessionName, password, workingDir string) {
	sessionDir := configDir + "/" + sessionName
	/* CREATES DIRECTORY FOR SESSION */
	err := os.Mkdir(sessionDir, 0777)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\tError: Can't create directory for '%s' session.\nError: %v\n", sessionName, err)
		os.Exit(1)
	}

	/* CREATES PERMISSION FILE */
	file, err := os.Create(sessionDir + "/" + sessionName + permissionFileSuffix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\tError: Can't create permissions file.\nError: ", err)
		os.Exit(1)
	}

	buf := make([]byte, maxFileInode)
	file.Write(buf)
	file.Close()

	/* CREATES JSON CONFIG */
	err = serverConfig.marshalAndSaveJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, "\tError: Can't save config in json file.\n\tError:", err)
		os.Exit(1)
	}

	file, err = os.Create(sessionDir + "/" + sessionName + passwordFileSuffix)
	if err != nil {
		e := err.(*os.PathError)
		fmt.Fprintf(os.Stderr, "\tError: Can't create file with users' info.\n\tDetails: %v\n", e.Err)
		os.Exit(1)
	}

	file.Write([]byte("root:"))
	passHash := sha256.Sum256([]byte(password))
	file.Write(passHash[:])
	file.Write([]byte("\n"))
	file.Close()

	fmt.Println("Working_dir:", workingDir)
	err = os.Mkdir(workingDir, 0777)
	if err != nil {
		e := err.(*os.PathError)
		fmt.Fprintf(os.Stderr, "\tError: Can't create main working dir.\n\tDetails: %v\n", e.Err)
		os.Exit(1)
	}
}

func (p *port) Set(value string) error {
	tmpVal, err := strconv.ParseUint(value, 10, 16)
	*p = port(tmpVal)
	return err
}

func (p *port) String() string {
	return fmt.Sprint(uint16(*p))
}

func (c *Info) marshalAndSaveJSON() error {
	jsonConfig, err := json.Marshal(tmpJSON{
		Address:    c.IPAddr.String(),
		Port:       c.portNumber,
		Session:    c.sessionName,
		WorkingDir: c.workingDirectory,
		Cipher:     c.doEncrypt,
	})
	if err != nil {
		return err
	}

	file, err := os.Create(configDir + "/" + c.sessionName + "/" + c.sessionName + configFileSuffix)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(jsonConfig)
	return err
}

func (c *Info) unmarshalFromFileJSON(sessionName string) error {
	file, err := os.Open(configDir + "/" + sessionName + "/" + sessionName + configFileSuffix)
	if err != nil {
		return err
	}

	jsonConfig, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	var tmp tmpJSON

	err = json.Unmarshal(jsonConfig, &tmp)
	if err != nil {
		return err
	}

	c.IPAddr = net.ParseIP(tmp.Address)
	c.portNumber = tmp.Port
	c.sessionName = tmp.Session
	c.doEncrypt = tmp.Cipher
	c.workingDirectory = tmp.WorkingDir

	return nil
}

// Address returns IP-address as string
func (c *Info) Address() string {
	return c.IPAddr.String()
}

// Port returns 'portNumber' of Info struct
func (c *Info) Port() uint16 {
	return uint16(c.portNumber)
}

// SessionName returns 'sessionName' of Info struct
func (c *Info) SessionName() string {
	return c.sessionName
}

// Cipher returns 'cipher' of Info struct
func (c *Info) Cipher() bool {
	return c.doEncrypt
}

// WorkingDirectory returns 'workingDirectory' of Info struct
func (c *Info) WorkingDirectory() string {
	return c.workingDirectory
}

// GetServerConfig returns server configuration
func GetServerConfig() Info {
	return serverConfig
}
