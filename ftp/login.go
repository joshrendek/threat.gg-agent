package ftp

import "github.com/joshrendek/threat.gg-agent/stats"

type AuthUser struct {
	username string
	password string
	valid    bool
}

func handleLogin(message string, user *AuthUser) string {
	// Handle login operations

	stats.Increment("ftp.logins")

	cmd, args, err := parseCommand(message)
	if err != nil {
		return SyntaxErr
	}

	switch {
	case cmd == "USER" && args == "":
		return AnonUserDenied
	case cmd == "USER" && args != "":
		user.username = args
		return UsrNameOkNeedPass
	case cmd == "PASS" && args == "":
		return SyntaxErr
	case cmd == "PASS" && args != "" && user.username != "":
		user.password = args
	}

	user.Authenticate()

	if user.valid == true {
		return UsrLoggedInProceed
	} else {
		user.username = ""
		user.password = ""
		return AuthFailureTryAgain
	}
}

func (user *AuthUser) Authenticate() {
	// Authenticate user against data.ambition

	/*
		uri := fmt.Sprint(DataUrl, "/api/upload/ftp-auth/")
		resp, err := http.PostForm(uri,
			url.Values{
				"username": {user.username},
				"password": {user.password}})

		if resp.StatusCode == http.StatusOK && err == nil {
			user.valid = true
		} else {
			user.valid = false
		}
	*/
	user.valid = true
}
