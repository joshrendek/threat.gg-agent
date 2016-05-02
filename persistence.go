package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	client = &http.Client{}
)

type SshLogin struct {
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Guid       string `json:"guid"`
	Version    string `json:"version"`
	PublicKey  []byte `json:"public_key"`
	KeyType    string `json:"key_type"`
	LoginType  string `json:"login_type"`
}

type ShellCommand struct {
	Cmd  string `json:"command"`
	Guid string `json:"guid"`
}

func (cmd *ShellCommand) Save() {
	o, err := json.Marshal(cmd)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	log.Printf("Sending ShellCommand Payload: %s", string(o))
	PostToApi("commands", postData)
}

func (login *SshLogin) Save() {
	o, err := json.Marshal(login)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	log.Printf("Sending Login Payload: %s", string(o))
	PostToApi("logins", postData)
}

func PostToApi(endpoint string, post_data *strings.Reader) {
	server_url := os.Getenv("SERVER_URL")
	if server_url == "" {
		server_url = "https://sshpot.com"
	}
	ssh_api := fmt.Sprintf("%s/api/%s", server_url, endpoint)
	req, err := http.NewRequest("POST", ssh_api, post_data)
	log.Println(fmt.Sprintf("[post] %s", ssh_api))
	_, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
}

func SaveHttpRequest(http_request map[string]string) {
	o, err := json.Marshal(http_request)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	fmt.Println(string(o))
	PostToApi("http", postData)
}
