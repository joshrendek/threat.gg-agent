package sshd

import (
	"fmt"
	"strings"

	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"github.com/rs/zerolog"
)

var (
	client = &http.Client{}
	logger = zerolog.New(os.Stdout).With().Caller().Str("persistence", "").Logger()
)

type CommandService struct {
}

type CommandRequest struct {
	Command string `json:"command"`
}

type CommandResponse struct {
	Response string `json:"response"`
}

func NewCommandService() *CommandService {
	return &CommandService{}
}

func (c *CommandService) GetCommandResponse(command string) *CommandResponse {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(&CommandRequest{Command: strings.TrimSpace(command)})
	apiKey := os.Getenv("API_KEY")
	server_url := os.Getenv("SERVER_URL")
	if server_url == "" {
		server_url = "https://threat.gg"
	}
	ssh_api := fmt.Sprintf("%s/api/command_response", server_url)
	req, err := http.NewRequest("POST", ssh_api, b)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Error().Err(err).Msg("failed to post to CommandResponse")
	}

	defer resp.Body.Close()
	cr := &CommandResponse{}
	json.NewDecoder(resp.Body).Decode(cr)
	logger.Info().Interface("body", cr).Msg("command response api response")
	return cr
}
