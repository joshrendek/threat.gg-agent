package ftp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

// maxFtpUploadBytes caps how large an FTP STOR upload we'll read back and ship to the
// server's file pipeline; matches the server's MaxDownloadBytes guard (64 MiB).
const maxFtpUploadBytes = 64 << 20

const (
	storageDir = "uploads"
)

type ConnectionConfig struct {
	DataConnectionAddr string
	Filename           string
}

func HandleConnection(c net.Conn, logger zerolog.Logger) {
	// Handle a connection from a client
	defer c.Close()

	sendMsg(c, FtpServerReady)
	user := AuthUser{guid: uuid.NewV4().String()}

	loginBreaker := 0
	for {
		message := getMsg(c)
		response := handleLogin(message, &user)
		sendMsg(c, response)
		if user.valid == true {
			break
		}
		loginBreaker++
		time.Sleep(100 * time.Millisecond)
		if loginBreaker > 10 {
			return
		}
	}

	go func() {
		loginDetails <- LoginDetails{Guid: user.guid, Username: user.username, Password: user.password, RemoteAddr: c.RemoteAddr().String()}
	}()

	config := ConnectionConfig{}

	for {
		cmd := getMsg(c)
		response, err := handleCommand(cmd, &config, &user, c, logger)
		if err != nil {
			break
		}
		sendMsg(c, response)
		time.Sleep(100 * time.Millisecond)
	}
}

func handleCommand(input string, ch *ConnectionConfig, user *AuthUser, c net.Conn, logger zerolog.Logger) (string, error) {
	// Handles input after authentication

	input = strings.TrimSpace(input)
	cmd, args, err := parseCommand(input)
	logger.Info().Str("command", input).Str("remote_ip", c.RemoteAddr().String()).Msg("command received from client")

	if err != nil {
		return SyntaxErr, err
	}

	// Server-authored response override (admin-editable command_responses, scoped to
	// command_type="ftp"), keyed by the raw command line. FTP replies are numeric-code
	// prefixed and carry their own trailing CRLF, and sendMsg writes verbatim, so an
	// authored response is returned as-is. On a miss/error we fall through to the hardcoded
	// replies below, so behavior never regresses if the server is unreachable.
	if resp, ok := cmdresp.LookupAndRecord("ftp", input, user.guid); ok {
		return resp, nil
	}

	ignoredCommands := []string{
		"CDUP", // cd to parent dir
		"RMD",  // remove directory
		"RNFR", // rename file from
		"RNTO", // rename file to
		"SIZE", // Size of a file
		"STAT", // Get status of FTP server
	}
	notImplemented := []string{
		"EPSV",
		"EPRT",
	}

	switch {
	case stringInList(cmd, ignoredCommands):
		return CmdNotImplmntd, nil
	case stringInList(cmd, notImplemented):
		return CmdNotImplmntd, nil
	case cmd == "SITE":
		fmt.Println(args)
		return CmdOk, nil
	case cmd == "NOOP":
		return CmdOk, nil
	case cmd == "SYST":
		return SysType, nil
	case cmd == "TYPE" && args == "A":
		return TypeSetOk, nil
	case cmd == "LIST" || cmd == "LPSV":
		out, _ := exec.Command("ls", "-l", "/").Output()
		//sendMsg(c, "229 Entering Extended Passive Mode (|||4089|)\r\n")
		sendMsg(c, "150 Opening ASCII mode data connection for file list\r\n")
		for _, line := range strings.Split(string(out), "\n") {
			sendMsg(c, line+"\r\n")
		}
		//return string(out), nil
		return CmdOk, nil
	case cmd == "STOR":
		ch.Filename = stripDirectory(args)
		readPortData(ch, user.username, c)
		go shipFtpUpload(user.guid, user.username, ch.Filename, logger)
		return TxfrCompleteOk, nil
	case cmd == "FEAT":
		return FeatResponse, nil
	case cmd == "PWD":
		return PwdResponse, nil
	case cmd == "TYPE" && args == "I":
		return TypeSetOk, nil
	case cmd == "PORT":
		ch.DataConnectionAddr = parsePortArgs(args)
		return PortOk, nil
	case cmd == "PASV":
		// todo set up PASV mode
		//return EnteringPasvMode, nil
		return CmdNotImplmntd, nil
	case cmd == "QUIT":
		return GoodbyeMsg, nil
	}
	return "", nil
}

func uploadData(user *AuthUser, filePath string) {
	//content, err := ioutil.ReadFile(filePath)
	//if err != nil {
	//	fmt.Printf("Error reading file %s: %s\n", filePath, err)
	//	return
	//}
	//_, filename := path.Split(filePath)

	//uri := fmt.Sprint(DataUrl, "/api/upload/ftp-upload/")

	//resp, err := http.PostForm(uri,
	//	url.Values{
	//		"username":       {user.username},
	//		"password":       {user.password},
	//		"local_filename": {filename},
	//		"data":           {string(content)}})

	//if resp.StatusCode == http.StatusCreated && err == nil {
	//	fmt.Printf("File %s uploaded to data!\n", filename)
	//	err = os.Remove(filePath)
	//	if err != nil {
	//		fmt.Printf("Error removing file %s: %s\n", filePath, err)
	//		return
	//	}
	//} else {
	//	fmt.Printf("Could not upload '%s' to data! %s\n", filePath, err)
	//}

}

func getFileName(username, filename string) string {
	return path.Join(storageDir, username, filename)
}

// shipFtpUpload reads back the file readPortData already wrote to disk and ships it to
// the server's file pipeline via SaveFile. Intended to be called with `go`, so a slow or
// unreachable server can never block the attacker's FTP session; failures are logged,
// never panicked.
func shipFtpUpload(guid, username, filename string, logger zerolog.Logger) {
	outputName := getFileName(username, filename)

	// Stat before read: readPortData streams the attacker-controlled upload to disk with
	// no byte cap, so we must bound memory BEFORE loading it, not after. Loading the whole
	// file into RAM first (the old order) lets a multi-GB STOR OOM the node even though the
	// size guard below exists.
	info, err := os.Stat(outputName)
	if err != nil {
		logger.Error().Err(err).Str("filename", filename).Msg("error stat'ing ftp upload for shipping")
		return
	}
	if info.Size() == 0 {
		return
	}
	if info.Size() > maxFtpUploadBytes {
		logger.Warn().Int64("size", info.Size()).Str("filename", filename).Msg("ftp upload exceeds size guard, not shipping to server")
		return
	}

	data, err := os.ReadFile(outputName)
	if err != nil {
		logger.Error().Err(err).Str("filename", filename).Msg("error reading back ftp upload for shipping")
		return
	}
	if err := persistence.SaveFile(data, filename, guid, "ftp"); err != nil {
		logger.Error().Err(err).Str("filename", filename).Msg("error shipping ftp upload to server")
	}
}

func readPortData(ch *ConnectionConfig, username string, out net.Conn) {
	// Read data from the client, write out to file
	fmt.Printf("connecting to %s\n", ch.DataConnectionAddr)

	var err error

	c, err := net.Dial("tcp", ch.DataConnectionAddr)
	// set timeout of one minute
	c.SetReadDeadline(time.Now().Add(time.Minute))
	defer c.Close()
	if err != nil {
		fmt.Printf("connection to %s errored out: %s\n", ch.DataConnectionAddr, err)
		return
	}
	sendMsg(out, DataCnxAlreadyOpenStartXfr)

	err = os.MkdirAll(path.Join(storageDir, username), 0777)
	if err != nil {
		fmt.Printf("error creating dir: %s\n", err)
		return
	}

	outputName := getFileName(username, ch.Filename)
	file, err := os.Create(outputName)
	defer file.Close()
	if err != nil {
		fmt.Printf("error creating file '%s': %s\n", outputName, err)
		return
	}

	reader := bufio.NewReader(c)
	buf := make([]byte, 1024) // big buffer
	for {
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Println("read error:", err)
			break
		}
		if n == 0 {
			break
		}
		if _, err := file.Write(buf[:n]); err != nil {
			fmt.Println("read error:", err)
			break
		}
	}
}

var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReader(nil)
	},
}

func getMsg(conn net.Conn) string {
	bufc := bufioReaderPool.Get().(*bufio.Reader)
	bufc.Reset(conn)
	defer bufioReaderPool.Put(bufc)

	lineBytes, err := bufc.ReadBytes('\n')
	if err != nil {
		_ = conn.Close()
		return ""
	}
	trimmedBytes := bytes.TrimRight(lineBytes, "\r")
	return string(trimmedBytes) // Convert to string only when necessary

}
func sendMsg(c net.Conn, message string) {
	//fmt.Printf("Sending: %s\n", message)
	io.WriteString(c, message)
}
