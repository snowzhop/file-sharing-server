package tcp

import (
	"eccrypto"
	"net"
)

const (
	additionalCipherBytes = 16          /*          */
	handshakeBufferSize   = 66          /*          */
	networkBufferSize     = 1024        /*          */
	sendingBufferSize     = 1024 * 1024 /*   1 MB   */
	lengthField           = 4           /* In bytes */
	commandField          = 1           /*          */
	authTokenField        = 4           /*          */
	responseHeaderLength  = 2           /*          */
	requestHeaderLength   = 5           /* command + auth-token = 1 + 4 = 5 */

	swapFileSuffix     = ".swp"
	connectionAttempts = 5
	testMessage        = "Test"
	testMsgBufLen      = 128
	expectedMsgBufLen  = len(testMessage) + 16
)

/* Server's responses */
const (
	RespOK byte = iota
	RespServerError
	RespClientError
	RespError
	RespFileIsUsing
	RespUndefinedFile
	RespTestError
)

/* Client's commands */
const (
	getFileListCommand  byte = iota // 0
	changeDirCommand                // 1
	downloadFileCommand             // 2
	renameFileCommand               // 3
	deleteFileCommand               // 4
	moveFileCommand                 // 5
	adminAuthCommand                // 6
	addAdminCommand                 // 7
)

// ClientConn describes client connection and contains opened directory by client
type ClientConn struct {
	net.TCPConn
	OpenedDirectory string
}

type clientInfo struct {
	workingFolder string
	cryptographer *eccrypto.ECcrypto
	remoteAddress string
}
