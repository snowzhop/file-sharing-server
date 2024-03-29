package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"eccrypto"

	"../config"
)

var serverConfig config.Info

// StartServer starts TCP server
// TODO add here channel for logger or smth else
func StartServer(conf config.Info) {
	addr, err := net.ResolveTCPAddr("tcp", conf.Address()+":"+strconv.FormatUint(uint64(conf.Port()), 10))

	// listener, err := net.Listen("tcp", conf.Address()+":"+strconv.FormatUint(uint64(conf.Port()), 10))
	listener, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		log.Printf("Error: server not started.")
		log.Printf("Description: %v\n", err)
		os.Exit(1)
	}

	serverConfig = conf

	log.Printf("Server %s has been started. Waiting for connections...", listener.Addr().String())

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("Failed to accept connection from %s\n", conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		log.Printf("Connection from %s\n", conn.RemoteAddr().String())

		// clConn := ClientConn{
		// 	TCPConn: *conn, OpenedDirectory: conf.WorkingDirectory(),
		// }

		go handleConn(conn)
	}

}

func handleConn(conn *net.TCPConn) {
	defer conn.Close()

	var ec eccrypto.ECcrypto

	connectionInfo := clientInfo{
		workingFolder: serverConfig.WorkingDirectory(), remoteAddress: conn.RemoteAddr().String(),
	}

	err := serverHandshake(conn, &ec)
	if err != nil {
		log.Printf("Can't make handshake with %s.\nDetails: %v", conn.RemoteAddr().String(), err)
		return
	}

	fmt.Printf("\tShared: %x\n", ec.Shared())
	networkBuffer := make([]byte, networkBufferSize)

	var mainBuffer []byte

	remoteAddress := conn.RemoteAddr().String()

	conn.SetReadDeadline(time.Now().Add(time.Minute * 5))
	for {
		mainBuffer = mainBuffer[:0]
		total := 0
		n, err := conn.Read(networkBuffer)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("connection %s timed out (5 min)", remoteAddress)
			break
		} else if err == io.EOF {
			log.Printf("Connection %s closed", remoteAddress)
			break
		} else if err != nil {
			log.Printf("Error: read from %s\n", remoteAddress)
		}

		mainBuffer = append(mainBuffer, networkBuffer[:n]...)

		total += len(networkBuffer[:n])

		// log.Printf("Got from %s: %s(%d)", remoteAddress, string(decryptedData[4:]), length)
		// fmt.Printf("len(buffer[:n]: %d\n", len(buffer[:n]))

		if n == networkBufferSize {
			fmt.Println("\t\tIN 'IF'")
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
			for {
				n, err = conn.Read(networkBuffer)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				if err == io.EOF {
					break
				}

				mainBuffer = append(mainBuffer, networkBuffer[:n]...)
				total += len(networkBuffer[:n])

			}
			conn.SetReadDeadline(time.Now().Add(time.Minute * 5))
		}

		decryptedRequest, err := ec.Decrypt(mainBuffer)
		if err != nil {
			log.Printf("Error: decryption: %v\n", err)
			break
		}
		// length := binary.LittleEndian.Uint32(decryptedData[:4])

		response := requestProcessing(decryptedRequest, &connectionInfo)

		encryptedResponse, err := ec.Encrypt(response)
		if err != nil {
			log.Printf("Error: encryption: %v", err)
			break
		}

		_, err = conn.Write(encryptedResponse)
		if err != nil {
			log.Printf("Error: send response: %v", err)
			break
		}

		log.Printf("Response sent to %s", connectionInfo.remoteAddress)

		// log.Printf("Got from %s: %s(%d) length: %d", remoteAddress, string(decryptedData[4:]), total, length)
	}
}

/* serverHandshake describes simple handshake between server and client
 * client   --connect->   server
 * client   --pubKey-->   server
 * client   <--pubkey--   server
 *          <calculate>
 * client    <private>    server
 *             <key>
 */
func serverHandshake(conn *net.TCPConn, ec *eccrypto.ECcrypto) error {
	clientPubKey := make([]byte, handshakeBufferSize)

	testBuf := make([]byte, testMsgBufLen)
	var err error

	for i := 0; i < connectionAttempts; i++ {
		log.Printf("Handshake attempt #%d", i+1)

		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err := conn.Read(clientPubKey)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Connection (%s) timeout.", conn.RemoteAddr().String())
			continue
			// return fmt.Errorf("connection timeout")
		}
		if n != handshakeBufferSize {
			return fmt.Errorf("wrong data (n(%d) != handshakeBufferSize(%d))", n, handshakeBufferSize)
		}
		conn.SetReadDeadline(time.Unix(0, 0))

		pubKey, err := ec.GenerateKeyPair()
		if err != nil {
			return err
		}

		packedPubKey := eccrypto.PackKey(pubKey.X, pubKey.Y)

		n, err = conn.Write(packedPubKey)
		if err != nil {
			return err
		}
		if n != len(packedPubKey) {
			return fmt.Errorf("data not sent completely")
		}

		x, y, err := eccrypto.UnpackKey(clientPubKey)
		if err != nil {
			return err
		}

		err = ec.CalculateSharedKey(x, y)
		if err != nil {
			return err
		}

		/* Test message */
		encryptedTestMsg, err := ec.Encrypt([]byte(testMessage))
		if err != nil {
			return fmt.Errorf("Can't encrypt test msg: %v", err)
		}

		_, err = conn.Write(encryptedTestMsg)
		if err != nil {
			return fmt.Errorf("Can't send test msg: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err = conn.Read(testBuf)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("Test msg reading timeout")
		}
		if n != expectedMsgBufLen {
			log.Printf("Wrong testMsg(encrypted) length: n(%d) != expectedMsgBufLen(%d)", n, expectedMsgBufLen)
			continue
		}

		decryptedTestMsg, err := ec.Decrypt(testBuf[:n])
		if err != nil {
			log.Printf("Test msg decrypting error: %v", err)
			continue
		}

		if bytes.Compare(decryptedTestMsg, []byte(testMessage)) == 0 {
			break
		}
		conn.SetReadDeadline(time.Unix(0, 0))

	}

	return err
}

func requestProcessing(request []byte, info *clientInfo) []byte {
	var response []byte

	command := request[0]

	switch command {
	case getFileListCommand:
		response = getFileList(info)
	case changeDirCommand:
		/* Add permission checking */
		response = changeDir(info, request[requestHeaderLength:])
	case downloadFileCommand:
		/* Add permission checking */
		response = sendFile(info, request[requestHeaderLength:])

	case renameFileCommand:
		/* Add permission checking */
		response = renameFile(info, request[requestHeaderLength:])

	case deleteFileCommand:
		/* Add permission checking */
		response = deleteFile(info, request[requestHeaderLength:])

	case moveFileCommand:
		/* Add permission checking */
		response = moveFile(info, request[requestHeaderLength:])

	case sendFileCommand:
		response = getFile(info, request[requestHeaderLength:])

	case adminAuthCommand:

	case addAdminCommand:
		/* Add permission checking */

	default: /* Error case */

	}

	return response
}

func intToByteSlice(value int) []byte {
	return []byte(strconv.Itoa(value))
}

func intToByteRepresentation(value uint32) []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, value)
	return ret
}

func createErrorResponse(command, errNumber byte) []byte {
	resp := make([]byte, 2)
	resp[0] = command
	resp[1] = errNumber
	return resp
}

func isSwapFileExists(currentDir, fileName []byte) bool {
	_, err := os.Stat(string(currentDir) + "/." + string(fileName) + swapFileSuffix)
	if err != nil {
		return false
	}
	return true
}

func createSwapFile(currentDir, fileName []byte) (*os.File, error) {
	return os.Create(string(currentDir) + "/." + string(fileName) + swapFileSuffix)
}

func deleteSwapFile(fileName string) {
	base := filepath.Base(fileName)

	if strings.HasPrefix(base, ".") && strings.HasSuffix(base, swapFileSuffix) {
		err := os.Remove(fileName)
		if err != nil {
			log.Printf("Error: can't delete swap file %s: %v\nRecommended manual removing.", fileName, err)
		}
		return
	}

	dir := filepath.Dir(fileName)

	swapName := dir + "/." + base + swapFileSuffix

	err := os.Remove(swapName)
	if err != nil {
		log.Printf("Error: can't delete swap file %s: %v\nRecommended manual removing.", swapName, err)
	}
}

func getFileList(info *clientInfo) []byte {
	fileListResponse := make([]byte, 2)
	fileListResponse[0] = getFileListCommand

	files, err := ioutil.ReadDir(info.workingFolder)
	if err != nil {
		fileListResponse[1] = RespServerError
		log.Print("Error: can't read directory")
		log.Printf("Details: %v", err)
		return fileListResponse
	}

	for _, file := range files {
		fileListResponse = append(fileListResponse, file.Name()...)
		if file.IsDir() {
			fileListResponse = append(fileListResponse, 'd')
		} else {
			fileListResponse = append(fileListResponse, intToByteRepresentation(uint32(file.Size()))...)
			fileListResponse = append(fileListResponse, 'f')
		}
		fileListResponse = append(fileListResponse, '#')
	}

	log.Printf("Created 'file list' for %s", info.remoteAddress)

	return fileListResponse
}

func changeDir(info *clientInfo, nextDir []byte) []byte {
	var response []byte

	if len(nextDir) != 0 {
		fileInfo, err := os.Stat(info.workingFolder + "/" + string(nextDir))
		if err != nil {
			response = createErrorResponse(changeDirCommand, RespServerError)
			log.Printf("Error: directory %s doesn't found\nDetails: %v", nextDir, err)
		} else if fileInfo.IsDir() {
			info.workingFolder += "/" + string(nextDir)
			response = getFileList(info)
			response[0] = changeDirCommand
			log.Printf("Working directory (%s) changed to %s", info.remoteAddress, nextDir)
		} else {
			response = createErrorResponse(changeDirCommand, RespUndefinedFile)
			log.Printf("Error: %s doesn't directory", nextDir)
		}
	} else {
		if strings.Compare(info.workingFolder, serverConfig.WorkingDirectory()) == 0 {
			response = createErrorResponse(changeDirCommand, RespClientError)
			log.Printf("Error: root directory reached")
		} else {
			lastSlashIndex := strings.LastIndexByte(info.workingFolder, '/')
			if lastSlashIndex == -1 {
				response = createErrorResponse(changeDirCommand, RespServerError)
				log.Printf("Error: wrong 'WorkingFolder' (server-side) format")
			} else {
				info.workingFolder = info.workingFolder[:lastSlashIndex]
				response = getFileList(info)
				response[0] = changeDirCommand
				log.Printf("Working directory (%s) changed to parent", info.remoteAddress)
			}
		}
	}

	return response
}

func renameFile(info *clientInfo, data []byte) []byte {
	var response []byte

	delimiterIndex := bytes.IndexByte(data, '#')

	if len(data) > 0 && delimiterIndex != -1 {
		oldName := data[:delimiterIndex]
		newName := data[delimiterIndex+1:]

		if !isSwapFileExists([]byte(info.workingFolder), oldName) {
			swapFile, err := createSwapFile([]byte(info.workingFolder), oldName)
			if err != nil {
				log.Printf("Error: can't create swap file %s: %v\n", oldName, err)
				response = createErrorResponse(renameFileCommand, RespServerError)
				return response
			}
			swapFile.Close()

			slashes := bytes.IndexByte(oldName, '/')
			if slashes != -1 {
				response = createErrorResponse(renameFileCommand, RespClientError)
				log.Printf("Error: wrong old file name.")

				deleteSwapFile(swapFile.Name())
				return response
			}

			slashes = bytes.IndexByte(newName, '/')
			if slashes != -1 {
				response = createErrorResponse(renameFileCommand, RespClientError)
				log.Printf("Error: wrong new file name.")

				deleteSwapFile(swapFile.Name())
				return response
			}

			oldNameStr := info.workingFolder + "/" + string(oldName)
			newNameStr := info.workingFolder + "/" + string(newName)

			err = os.Rename(oldNameStr, newNameStr)
			if err != nil {
				response = createErrorResponse(renameFileCommand, RespError)
				linkErr := err.(*os.LinkError)
				response = append(response, []byte(linkErr.Err.Error())...)
				log.Printf("Error: can't rename %s to %s: %s", linkErr.Old, linkErr.New, linkErr.Err.Error())

				deleteSwapFile(swapFile.Name())
				return response
			}

			log.Printf("%s renamed to %s", oldNameStr, newNameStr)

			deleteSwapFile(swapFile.Name())

			response = getFileList(info)
			response[0] = renameFileCommand
		} else {
			response = createErrorResponse(renameFileCommand, RespFileIsUsing)
		}
	} else {
		response = createErrorResponse(renameFileCommand, RespClientError)
	}
	return response
}

func moveFile(info *clientInfo, data []byte) []byte {
	var response []byte

	delimiterIndex := bytes.IndexByte(data, '#')

	if len(data) > 0 && delimiterIndex != -1 {
		oldName := data[:delimiterIndex]
		newPath := data[delimiterIndex+1:]

		if !isSwapFileExists([]byte(info.workingFolder), oldName) {
			swapFile, err := createSwapFile([]byte(info.workingFolder), oldName)
			if err != nil {
				log.Printf("Error: can't create swap file %s: %v\n", oldName, err)
				response = createErrorResponse(renameFileCommand, RespServerError)
				return response
			}
			swapFile.Close()

			if bytes.IndexByte(oldName, '/') != -1 {
				response = createErrorResponse(moveFileCommand, RespClientError)
				log.Printf("Error: wrong old file name.")

				deleteSwapFile(swapFile.Name())
				return response
			}

			newPathInfo, err := os.Stat(serverConfig.WorkingDirectory() + "/" + string(newPath))
			if err != nil {
				response = createErrorResponse(moveFileCommand, RespError)
				pathErr := err.(*os.PathError)
				response = append(response, []byte(pathErr.Err.Error())...)
				log.Printf("Error: can't do stat: %v", err)

				deleteSwapFile(swapFile.Name())
				return response
			}

			if !newPathInfo.IsDir() {
				response = createErrorResponse(moveFileCommand, RespClientError)
				log.Printf("Error: wrong new path. %s is a file.", newPathInfo.Name())

				deleteSwapFile(swapFile.Name())
				return response
			}

			if bytes.Compare(newPath, []byte("..")) == 0 {
				newPath = []byte("")
			} else {
				newPath = append(newPath, '/')
			}

			oldPathStr := info.workingFolder + "/" + string(oldName)
			newPathStr := serverConfig.WorkingDirectory() + "/" + string(newPath) + string(oldName)

			err = os.Rename(oldPathStr, newPathStr)
			if err != nil {
				response = createErrorResponse(moveFileCommand, RespError)
				linkErr := err.(*os.LinkError)
				response = append(response, []byte(linkErr.Err.Error())...)
				log.Printf("Error: can't move %s to %s: %s", linkErr.Old, linkErr.New, linkErr.Err.Error())

				deleteSwapFile(swapFile.Name())
				return response
			}

			log.Printf("%s moved to %s", oldPathStr, newPathStr)

			deleteSwapFile(swapFile.Name())

			response = getFileList(info)
			response[0] = moveFileCommand

		} else {
			response = createErrorResponse(renameFileCommand, RespFileIsUsing)
		}
	}

	return response
}

func getFile(info *clientInfo, data []byte) []byte {
	var response []byte

	if len(data) > 0 && !isSwapFileExists([]byte(info.workingFolder), data) {
		swapFile, err := createSwapFile([]byte(info.workingFolder), data)
		if err != nil {
			log.Printf("Error: can't create swap file %s: %v", swapFile.Name(), err)
			response = createErrorResponse(sendFileCommand, RespServerError)
			return response
		}
		/* Swap file will be deleted in sendFileToClient() goroutine */

		fileToReceive := info.workingFolder + "/" + string(data)

		_, err = os.Stat(fileToReceive)
		if err == nil {
			log.Printf("Error: file %s already exists.", fileToReceive)

			response = createErrorResponse(sendFileCommand, RespClientError)
			response = append(response, []byte("File already exists")...)
			deleteSwapFile(swapFile.Name())
			return response
		}

		addr, err := net.ResolveTCPAddr("tcp", serverConfig.Address()+":0")
		if err != nil {
			log.Printf("Error: can't resolve address for sending listener.\nDetails: %v", err)
			response = createErrorResponse(sendFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			log.Printf("Error: can't create new listener for file sending.\nDetails: %v", err)
			response = createErrorResponse(sendFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
			response = make([]byte, 2)
			response[0] = sendFileCommand
			response[1] = RespOK
			response = append(response, data...)
			response = append(response, '#')
			response = append(response, intToByteSlice(tcpAddr.Port)...)
		} else {
			log.Printf("Error: can't get new listener's port")
			response = createErrorResponse(sendFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		log.Printf("New listener (%s) was created for file receiving.", listener.Addr().String())

		go getFileFromClient(listener, fileToReceive)

	} else {
		response = createErrorResponse(sendFileCommand, RespClientError)
		response = append(response, []byte("Such file already exists or empty request")...)
	}
	return response
}

func getFileFromClient(listener *net.TCPListener, fileToGet string) {
	defer deleteSwapFile(fileToGet)

	log.Printf("\tFILE: %s", fileToGet)
	listener.SetDeadline(time.Now().Add(time.Second * additionalConnTimeout)) // 40 seconds deadline
	listenerAddr := listener.Addr().String()

	conn, err := listener.AcceptTCP()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Error(%s): timeout accepting error.", listenerAddr)
			return
		}
		log.Printf("Error(%s): accepting error.\nDetails: %v", listenerAddr, err)
		return
	}
	defer conn.Close()

	var localEc eccrypto.ECcrypto
	err = serverHandshake(conn, &localEc)
	if err != nil {
		log.Printf("Failed handshake with %s.\nDetails: %v", conn.RemoteAddr().String(), err)
		return
	}

	log.Printf("Local (GET) shared: %x", localEc.Shared())

	file, err := os.Create(fileToGet)
	if err != nil {
		log.Printf("Error (%s): can't save file %s", listenerAddr, fileToGet)
		return
	}
	defer file.Close()

	tmpBuf := make([]byte, receivingBufferSize)
	var cache []byte

	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	for {
		n, err := conn.Read(tmpBuf)
		if err == io.EOF {
			parts := len(cache) / receivingBufferSize

			log.Printf("Last: len(cache): %d\tparts(end): %d", len(cache), parts)

			for i := 0; i < parts; i++ {
				err := decryptAndSave(file, &localEc, cache[receivingBufferSize*i:receivingBufferSize*(i+1)])
				if err != nil {
					log.Printf("Error (%s):Can't save decrypt/write last part of information to file: %v", listenerAddr, err)
					return
				}
			}

			err := decryptAndSave(file, &localEc, cache[receivingBufferSize*parts:])
			if err != nil {
				log.Printf("Error (%s): can't decrypt/write last part of data: %v", listenerAddr, err)
				return
			}

			break

		} else if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("Error (%s): connection timeout.", listenerAddr)
				return
			}
			log.Printf("Error: %v", err)
			return
		}

		buffer := append(cache, tmpBuf[:n]...)
		parts := len(buffer) / receivingBufferSize

		log.Printf("Parts: %d\tn: %d\tlen(buffer): %d", parts, n, len(buffer))

		var i int
		for i = 0; i < parts; i++ {
			log.Printf("RBS*i: %d\tRBS*(i+1): %d", receivingBufferSize*i, receivingBufferSize*(i+1))
			err := decryptAndSave(file, &localEc, buffer[receivingBufferSize*i:receivingBufferSize*(i+1)])
			if err != nil {
				log.Printf("Error: can't decrypt/write data: %v", err)
				return
			}
		}

		log.Printf("len(cache): %d\tlen(buffer): %d", len(cache), len(buffer))
		cache = make([]byte, len(buffer)-parts*receivingBufferSize)
		copy(cache, buffer[parts*receivingBufferSize:])
		log.Printf("len(cache): %d\tlen(buffer): %d", len(cache), len(buffer))

		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 1500))

	}

	log.Printf("(%s) File %s received", listenerAddr, fileToGet)

}

func decryptAndSave(file *os.File, cryptograph *eccrypto.ECcrypto, data []byte) error {
	decrypted, err := cryptograph.Decrypt(data)
	if err != nil {
		return err
	}

	_, err = file.Write(decrypted)
	if err != nil {
		return err
	}

	return nil
}

func sendFile(info *clientInfo, data []byte) []byte {
	var response []byte

	if len(data) > 0 && !isSwapFileExists([]byte(info.workingFolder), data) {
		swapFile, err := createSwapFile([]byte(info.workingFolder), data)
		if err != nil {
			log.Printf("Error: can't create swap file %s: %v\n", data, err)
			response = createErrorResponse(downloadFileCommand, RespError)
			return response
		}
		/* Swap file will be deleted in sendFileToClient() goroutine */

		fileToSend := info.workingFolder + "/" + string(data)

		addr, err := net.ResolveTCPAddr("tcp", serverConfig.Address()+":0")
		if err != nil {
			log.Printf("Error: can't resolve address for sending listener.\nDetails: %v", err)
			response = createErrorResponse(downloadFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			log.Printf("Error: can't create new listener for file sending\nDetails: %v", err)
			response = createErrorResponse(downloadFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		fileInfo, err := os.Stat(fileToSend)
		if err != nil {
			pathError := err.(*os.PathError)
			response = createErrorResponse(downloadFileCommand, RespError)
			response = append(response, []byte(pathError.Err.Error())...)
			log.Printf("Error: file (%s) checking: %s", pathError.Path, pathError.Err.Error())
			deleteSwapFile(swapFile.Name())
			return response
		}
		if fileInfo.IsDir() {
			log.Printf("Error: file (%s) is a directory", fileToSend)
			response = createErrorResponse(downloadFileCommand, RespClientError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
			response = make([]byte, 2)
			response[0] = downloadFileCommand
			response[1] = RespOK
			response = append(response, data...)
			response = append(response, '#')
			response = append(response, intToByteSlice(tcpAddr.Port)...)
		} else {
			log.Printf("Error: can't get new listener's port")
			response = createErrorResponse(downloadFileCommand, RespServerError)
			deleteSwapFile(swapFile.Name())
			return response
		}

		log.Printf("New listener (%s) was created", listener.Addr().String())

		go sendFileToClient(listener, fileToSend)

	} else {
		log.Printf("Error: empty file name or file is using now (%s).", string(data))
		response = createErrorResponse(downloadFileCommand, RespClientError)
	}

	return response
}

func sendFileToClient(listener *net.TCPListener, fileToSend string) {
	defer deleteSwapFile(fileToSend)

	listener.SetDeadline(time.Now().Add(time.Second * additionalConnTimeout)) // 40 seconds deadline
	listenerAddr := listener.Addr().String()

	conn, err := listener.AcceptTCP()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Error(%s): timeout accepting error.", listenerAddr)
			return
		}
		log.Printf("Error(%s): accepting error.\nDetails: %v", listenerAddr, err)
		return
	}
	defer conn.Close()

	log.Printf("(%s)Connected from %s", listenerAddr, conn.RemoteAddr().String())

	remoteAddr := conn.RemoteAddr().String()

	file, err := os.Open(fileToSend)
	if err != nil {
		pathErr := err.(*os.PathError)
		log.Printf("Error(%s): can't open file %s: %s", listenerAddr, fileToSend, pathErr.Err.Error())
		return
	}

	var localEc eccrypto.ECcrypto
	err = serverHandshake(conn, &localEc)
	if err != nil {
		log.Printf("Failed handshake with %s.\nDetails: %v", conn.RemoteAddr().String(), err)
		return
	}

	log.Printf("Local (SEND) shared: %x", localEc.Shared())

	sendingBuffer := make([]byte, sendingBufferSize)
	total := int64(0)

	conn.SetDeadline(time.Now().Add(time.Second * 6))
	for {
		n, err := file.Read(sendingBuffer)
		if err == io.EOF {
			log.Printf("\tBREAK")
			break
		} else if err != nil {
			log.Printf("Error(%s): can't read file (%s) info.\nDetails: %v", listenerAddr, fileToSend, err)
			return
		}

		log.Printf("\tREAD FROM FILE: %d", n)

		/* 2 */
		encryptedData, err := localEc.Encrypt(sendingBuffer[:n])
		if err != nil {
			log.Printf("Error: can't encypt read data: %v", err)
			return
		}

		sent, err := conn.Write(encryptedData)
		if err != nil {
			log.Printf("Error(%s): can't send data to %s.", listenerAddr, remoteAddr)
			return
		}

		log.Printf("\tWRITTEN: %d", sent)

		conn.SetDeadline(time.Now().Add(time.Second))

		total += int64(sent)
	}

	log.Printf("File %s was sent to %s (%d bytes).", fileToSend, remoteAddr, total)

}

func deleteFile(info *clientInfo, data []byte) []byte {
	var response []byte

	if !isSwapFileExists([]byte(info.workingFolder), data) {
		swapFile, err := createSwapFile([]byte(info.workingFolder), data)
		if err != nil {
			log.Printf("Error: can't create swap file %s: %v", swapFile.Name(), err)
			response = createErrorResponse(deleteFileCommand, RespServerError)
			return response
		}

		_, err = os.Stat(info.workingFolder + "/" + string(data))
		if err != nil {
			pathErr := err.(*os.PathError)
			log.Printf("Error: can't get file stats: %v", pathErr.Err.Error())

			response = createErrorResponse(deleteFileCommand, RespError)
			response = append(response, []byte(pathErr.Err.Error())...)
			return response
		}

		err = os.RemoveAll(info.workingFolder + "/" + string(data))
		if err != nil {
			log.Printf("Error: can't delete file %s: %v", string(data), err)
			response = createErrorResponse(deleteFileCommand, RespServerError)
			return response
		}

		log.Printf("File %s was deleted", string(data))
		deleteSwapFile(swapFile.Name())

		response = getFileList(info)
		response[0] = deleteFileCommand

	} else {
		response = createErrorResponse(deleteFileCommand, RespFileIsUsing)
	}

	return response
}
