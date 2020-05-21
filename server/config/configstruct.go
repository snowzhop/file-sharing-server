package config

import "net"

type port uint16

const (
	defaultWorkingDirName = "Working_dir"
	projectName           = "bonch_files"
	configFileSuffix      = "_config.json"
	permissionFileSuffix  = "_perm"
	passwordFileSuffix    = "_u"
	defaultPort           = 9999
	maxPort               = 65535
	maxFileInode          = 32 * 1024 * 1024 / 4 /* = 8388608 */
)

var (
	// homeDir   string
	configDir string
)

type tmpJSON struct {
	Address    string `json:"address"`
	Port       port   `json:"port"`
	Session    string `json:"session-name"`
	WorkingDir string `json:"working-dir"`
	Cipher     bool   `json:"cipher"`
}

// Info describes user's config for server
type Info struct {
	IPAddr           net.IP
	portNumber       port
	sessionName      string
	doEncrypt        bool
	workingDirectory string
}

// InfoConfig variable provides user information about server
var serverConfig Info
