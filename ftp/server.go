package ftp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

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
	user := AuthUser{}

	for {
		message := getMsg(c)
		response := handleLogin(message, &user)
		sendMsg(c, response)
		if user.valid == true {
			break
		}
	}

	go func() {
		loginDetails <- LoginDetails{Username: user.username, Password: user.password, RemoteAddr: c.RemoteAddr().String()}
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
		// Don't upload for now
		//go uploadData(user, getFileName(user.username, ch.Filename))
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
	// Upload to data.ambition

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

func getMsg(conn net.Conn) string {
	// Split the response into CMD and ARGS
	bufc := bufio.NewReader(conn)
	for {
		line, err := bufc.ReadString('\n')
		if err != nil {
			conn.Close()
			break
		}
		fmt.Printf("Received: %s\n", line)
		return strings.TrimRight(line, "\r")
	}
	return ""
}

func sendMsg(c net.Conn, message string) {
	fmt.Printf("Sending: %s\n", message)
	io.WriteString(c, message)
}
