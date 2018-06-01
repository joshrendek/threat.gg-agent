package persistence

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	client = &http.Client{}
)

type FtpAttack struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RemoteAddr string `json:"remote_addr"`
	Guid       string `json:"guid"`
}

func (hr *FtpAttack) Save() {
	o, err := json.Marshal(hr)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	//log.Printf("Sending HttpRequest Payload: %s", string(o))
	PostToApi("ftp", postData)
}

type EsAttack struct {
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	RemoteAddr string            `json:"remote_addr"`
	Headers    map[string]string `json:"headers"`
	Path       string            `json:"path"`
	FormData   map[string]string `json:"form_data"`
	Method     string            `json:"method"`
	Guid       string            `json:"guid"`
	Hostname   string            `json:"hostname"`
	UserAgent  string            `json:"user_agent"`
}

func (hr *EsAttack) Save() {
	o, err := json.Marshal(hr)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	//log.Printf("Sending HttpRequest Payload: %s", string(o))
	PostToApi("elasticsearch", postData)
}

type HttpAttack struct {
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	RemoteAddr string            `json:"remote_addr"`
	Headers    map[string]string `json:"headers"`
	Path       string            `json:"path"`
	FormData   map[string]string `json:"form_data"`
	Method     string            `json:"method"`
	Guid       string            `json:"guid"`
	Hostname   string            `json:"hostname"`
	UserAgent  string            `json:"user_agent"`
}

func (hr *HttpAttack) Save() {
	o, err := json.Marshal(hr)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	//log.Printf("Sending HttpRequest Payload: %s", string(o))
	PostToApi("http_services", postData)
}

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

type HttpRequest struct {
	Headers  http.Header `json:"headers"`
	URL      string      `json:"url"`
	FormData url.Values  `json:"form_data"`
	Method   string      `json:"method"`
	Guid     string      `json:"guid"`
	Hostname string      `json:"hostname"`
	Response string      `json:"response"`
}

type ShellCommand struct {
	Cmd  string `json:"command"`
	Guid string `json:"guid"`
}

func (hr *HttpRequest) Save() {
	o, err := json.Marshal(hr)
	if err != nil {
		panic(err)
	}
	postData := strings.NewReader(string(o))
	//log.Printf("Sending HttpRequest Payload: %s", string(o))
	PostToApi("http_requests", postData)
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
	apiKey := os.Getenv("API_KEY")
	server_url := os.Getenv("SERVER_URL")
	if server_url == "" {
		server_url = "https://hnypots.com"
	}
	ssh_api := fmt.Sprintf("%s/api/%s?api_key=%s", server_url, endpoint, apiKey)
	req, err := http.NewRequest("POST", ssh_api, post_data)
	log.Println(fmt.Sprintf("[post] %s", ssh_api))

	if os.Getenv("DEBUG") != "" {
		log.Printf("[debug] %+v", post_data)
		return
	}
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
