package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"eccrypto"
)

const (
	serverBuffer  = 24
	headerLength  = 5
	bigBufferSize = 1024*1024 + 16

	connectionAttempts = 5
	testMessage        = "Test"
	testMsgBufLen      = 30
	expectedMsgBufLen  = len(testMessage) + 16
)

var ec eccrypto.ECcrypto

var serverAddress string = "127.0.0.1"

var workingDir string = "/"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Set port")
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", serverAddress+":"+os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't connect to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	err = clientHandshake(&conn, &ec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed handshake: %v\n", err)
		os.Exit(1)
	}

	input := bufio.NewScanner(os.Stdin)

	megaBuffer := make([]byte, 1024*10)

	fmt.Print("Command > ")
	for input.Scan() {
		tmpCommand := input.Bytes()[:1]
		var command []byte

		for {
			command = byteToSlice(tmpCommand)
			if command != nil {
				break
			}
			fmt.Print("Command > ")
			input.Scan()
			tmpCommand = input.Bytes()[:1]
		}

		fmt.Print("Data > ")
		input.Scan()
		data := input.Bytes()

		completeData := make([]byte, len(data)+headerLength)

		n := copy(completeData, command)
		copy(completeData[headerLength:], data)

		encryptedData, err := ec.Encrypt(completeData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Encryption error: %v\n", err)
			break
		}

		_, err = conn.Write(encryptedData)
		if err != nil {
			fmt.Printf("Error: send error: %v\n", err)
			break
		}

		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err = conn.Read(megaBuffer)
		if err != nil {
			fmt.Printf("Error: read error: %v\n", err)
			break
		}

		responseProcessing(megaBuffer[:n])

		fmt.Print("Command > ")

		conn.SetReadDeadline(time.Now().Add(time.Minute * 5))
	}
	fmt.Println()
}

func uintToSlice(value uint32) []byte {
	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, value)

	return ret
}

func byteToSlice(value []byte) []byte {
	tmp, err := strconv.ParseUint(string(value), 10, 8)
	if err != nil {
		return nil
	}

	ret := make([]byte, 1)
	ret[0] = uint8(tmp)

	return ret

}

func responseProcessing(data []byte) {
	decryptedData, err := ec.Decrypt(data)

	if err != nil {
		fmt.Printf("Error: decryption: %v\n", err)
		return
	}

	if decryptedData != nil {
		command := decryptedData[0]
		answer := decryptedData[1]

		fmt.Printf("Command: %#08b\tAnswer: %#08b\n", command, answer)

		if answer == 0 {
			switch command {
			case byte(0):
				printFileList(decryptedData[2:])
			case byte(1):
				printFileList(decryptedData[2:])

			case byte(2):
				if len(decryptedData[2:]) > 0 {
					fmt.Printf("\tDATA: %s\n", decryptedData[2:])
				}
				go getFile(decryptedData[2:])
			case byte(3):
				if len(decryptedData[2:]) > 0 {
					printFileList(decryptedData[2:])
				}
			case byte(4):
				if len(decryptedData[2:]) > 0 {
					printFileList(decryptedData[2:])
				}
			case byte(5):
				if len(decryptedData[2:]) > 0 {
					printFileList(decryptedData[2:])
				}
			case byte(6):
			case byte(7):
			default:
			}
		} else {
			fmt.Printf("ERROR: %08b\n", answer)
		}
	}
}

func clientHandshake(conn *net.Conn, ecdh *eccrypto.ECcrypto) error {
	buffer := make([]byte, 66)
	testBuf := make([]byte, testMsgBufLen)
	var err error

	for i := 0; i < connectionAttempts; i++ {
		log.Printf("Handshake attempt #%d", i+1)

		pubKey, err := ecdh.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("Error: GenerateKeyPair(): %v", err)
			// os.Exit(1)
		}
		packedPubKey := eccrypto.PackKey(pubKey.X, pubKey.Y)

		n, err := (*conn).Write(packedPubKey)
		if err != nil {
			return fmt.Errorf("Error: Writing packedKey: %v", err)
			// os.Exit(1)
		}
		if n != len(packedPubKey) {
			return fmt.Errorf("Error: data not sent completely")
			// os.Exit(1)
		}

		(*conn).SetReadDeadline(time.Now().Add(time.Second * 5))

		n, err = (*conn).Read(buffer)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("Timeout error: %v", netErr)
			// os.Exit(1)
		} else if err != nil {
			return fmt.Errorf("Error: %v", err)
			// os.Exit(1)
		}

		// (*conn).SetReadDeadline(time.Now().Add(time.Minute * 5))

		x, y, err := eccrypto.UnpackKey(buffer[:n])
		if err != nil {
			return fmt.Errorf("Error: Can't unpack key: %v", err)
			// os.Exit(1)
		}

		err = ecdh.CalculateSharedKey(x, y)
		if err != nil {
			return fmt.Errorf("Error: can't calculate shared key: %v", err)
			// os.Exit(1)
		}

		/* Test message */
		(*conn).SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err = (*conn).Read(testBuf)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("Error: reading test msg timeout")
			// os.Exit(1)
		}
		if n != expectedMsgBufLen {
			fmt.Printf("Wrong test msg len: n(%d) != expectedMsgBufLen(%d)\n", n, expectedMsgBufLen)
			continue
		}
		(*conn).SetReadDeadline(time.Now().Add(time.Minute * 5))

		decryptedTestMsg, err := ecdh.Decrypt(testBuf[:n])
		if err != nil {
			fmt.Printf("Can't decrypt test msg: %v\n", err)
			continue
		}

		encryptedTestMsg, err := ecdh.Encrypt([]byte(testMessage))
		if err != nil {
			return fmt.Errorf("Can't encrypt test msg: %v", err)
			// os.Exit(1)
		}

		_, err = (*conn).Write(encryptedTestMsg)
		if err != nil {
			return fmt.Errorf("Can't send encrypted test msg: %v", err)
			// os.Exit(1)
		}

		if bytes.Compare(decryptedTestMsg, []byte(testMessage)) == 0 {
			break
		}
	}

	if err != nil {
		return fmt.Errorf("Unexpected error: %v", err)
		// os.Exit(1)
	}

	fmt.Printf("Shared key: %x\n", ecdh.Shared())
	return nil
}

func printFileList(data []byte) {
	files := bytes.Split(data, []byte("#"))
	fmt.Println()
	for _, line := range files {
		fmt.Printf("%s\t%s\n", line[:len(line)], line[len(line):])
	}
}

func getFile(data []byte) {
	delimiterIndex := bytes.IndexByte(data, '#')
	if delimiterIndex == -1 {
		fmt.Fprintf(os.Stderr, "Error: wrong data format: %s\n", data)
		return
	}

	fileName := data[:delimiterIndex]
	port := data[delimiterIndex+1:]

	conn, err := net.Dial("tcp", serverAddress+":"+string(port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: can't get new file from %s\n", serverAddress+":"+string(port))
		return
	}

	fmt.Println("Connected to server")

	var localEc eccrypto.ECcrypto

	err = clientHandshake(&conn, &localEc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Handshake error: %v\n", err)
		return
	}
	fmt.Printf("Local shared: %x\n", localEc.Shared())

	file, err := os.Create("/home/polycarp/Temporary_files/" + string(fileName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: can't create new %s file\n", string(fileName))
		return
	}
	defer file.Close()

	tmpBuf := make([]byte, bigBufferSize) // 2
	var cache []byte                      // 2

	logs, _ := os.Create("/home/polycarp/Temporary_files/logs")
	log.SetOutput(logs)
	defer logs.Close()

	// buffer := make([]byte, 1024*1024)  // 1

	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	for {
		// n, err := conn.Read(buffer) // 1
		n, err := conn.Read(tmpBuf)
		if err == io.EOF {
			parts := len(cache) / bigBufferSize

			log.Printf("Last: len(cache): %d\tparts(end): %d", len(cache), parts)

			for i := 0; i < parts; i++ {
				err := decryptAndSave(file, &localEc, cache[bigBufferSize*i:bigBufferSize*(i+1)])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: can't decrypt or write last part of data (in cycle): %v\n", err)
					return
				}
			}

			err := decryptAndSave(file, &localEc, cache[bigBufferSize*parts:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: can't decrypt or write last part of data: %v\n", err)
				return
			}

			break
		} else if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Fprintf(os.Stderr, "Error: timeout (%s)\n", string(fileName))
				break
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			break
		}

		/* 2 */
		buffer := append(cache, tmpBuf[:n]...)
		parts := len(buffer) / bigBufferSize

		log.Printf("Parts: %d\tn: %d\tlen(buffer): %d", parts, n, len(buffer))

		var i int
		for i = 0; i < parts; i++ {
			log.Printf("BBS*i: %d\t BBS*(i+1): %d", bigBufferSize*i, bigBufferSize*(i+1))
			err := decryptAndSave(file, &localEc, buffer[bigBufferSize*i:bigBufferSize*(i+1)])
			if err != nil {
				fmt.Printf("Error: can't decrypt and write data: %v\n", err)
				return
			}
		}

		log.Printf("len(cache): %d\tlen(buffer): %d", len(cache), len(buffer))
		cache = make([]byte, len(buffer)-parts*bigBufferSize)
		copy(cache, buffer[parts*bigBufferSize:])
		log.Printf("len(cache): %d\tlen(buffer): %d", len(cache), len(buffer))

		log.Print("end")

		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 1000))

	}

	fmt.Printf("File %s saved\n", fileName)
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
