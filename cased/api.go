package cased

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

var session_id string
var session_id_form string
var xsrf string
var jwt string
var cs_token string

// Error message to wrap tea.Msg across API functions.
type ErrMsg struct{ err error }

func (e ErrMsg) Error() string { return e.err.Error() }

// Helper to create a http request with cookies and headers
// properly set in order to connect to the cased shell.
func createRequest(path, method string, args url.Values) (*http.Response, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return &http.Response{}, err
	}

	client := http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var req *http.Request

	if method == "POST" {
		if len(xsrf) > 0 {
			args.Add("_xsrf", xsrf)
		}
		if len(session_id_form) > 0 {
			args.Add("session_id", session_id_form)
		}
		req, err = http.NewRequest(method, path, strings.NewReader(args.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, path, nil)
		req.URL.RawQuery = args.Encode()
	}

	if err != nil {
		return &http.Response{}, err
	}

	// Add token cookie
	cookie := &http.Cookie{
		Name:   "token",
		Value:  jwt,
		MaxAge: 24 * 3600,
	}
	req.AddCookie(cookie)

	// Add session_id cookie
	if session_id != "" {
		sid_cookie := &http.Cookie{
			Name:   "session_id",
			Value:  session_id,
			MaxAge: 24 * 3600,
		}
		req.AddCookie(sid_cookie)
	}

	if xsrf != "" {
		// Add xsrf cookie
		xsrf_cookie := &http.Cookie{
			Name:   "_xsrf",
			Value:  xsrf,
			MaxAge: 24 * 3600,
		}
		req.AddCookie(xsrf_cookie)
	}

	if cs_token != "" {
		cs_tk_cookie := &http.Cookie{
			Name:   "cs_token",
			Value:  cs_token,
			MaxAge: 24 * 3600,
		}
		req.AddCookie(cs_tk_cookie)
	}

	if session_id == "" {
		req.Header.Set("Token", os.Getenv("CASED_TOKEN"))
	}

	resp, err := client.Do(req)
	if err != nil {
		return &http.Response{}, err
	}

	return resp, err
}

func login() error {
	if session_id != "" {
		return nil // already logged in
	}

	args := url.Values{}
	args.Add("email", "admin@cased.dev")

	for _, method := range []string{"GET", "POST"} {
		resp, _, err := sendRequestImpl("/v2/developer", method, args)
		if err != nil {
			return err
		}

		if method == "GET" {
			xsrf = find(resp, "_xsrf")
			if xsrf == "" {
				return errors.New("Unable to find _xsrf")
			}
		}
	}

	resp, _, err := sendRequestImpl("/v2/", "GET", args)
	if err != nil {
		return err
	}

	session_id_form = find(resp, "session_id")
	if session_id_form == "" {
		return errors.New("Unable to find session_id")
	}

	xsrf = find(resp, "_xsrf")
	if xsrf == "" {
		return errors.New("Unable to find _xsrf")
	}

	return nil
}

func sendRequestImpl(endpoint, method string, args url.Values) (string, map[string]string, error) {
	cased_host := os.Getenv("CASED_SHELL_HOSTNAME")
	api_url := fmt.Sprintf("http://%s%s", cased_host, endpoint)

	resp, err := createRequest(api_url, method, args)
	if err != nil {
		return "", nil, err
	}

	defer resp.Body.Close()

	// Print response headers
	// for k, v := range resp.Header {
	// 	fmt.Print(k)
	// 	fmt.Print(" : ")
	// 	fmt.Println(v)
	// }

	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return "", nil, errors.New(resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	cookies := map[string]string{}

	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "session_id":
			session_id = cookie.Value
		case "cs_token":
			cs_token = cookie.Value
		case "token":
			jwt = cookie.Value
		}

		cookies[cookie.Name] = cookie.Value
	}

	return string(body), cookies, nil
}

func sendRequest(endpoint, method string, args url.Values) (string, map[string]string, error) {
	var err error

	if session_id == "" {
		err = login()
		if err != nil {
			os.Stderr.WriteString("[*] Login to cased shell failed:\n" + err.Error())
			os.Stderr.WriteString("CASED_SHELL_HOSTNAME: " + os.Getenv("CASED_SHELL_HOSTNAME"))
			return "", nil, nil
		}
	}

	return sendRequestImpl(endpoint, method, args)
}

func GET(endpoint string, args url.Values) (string, map[string]string, error) {
	return sendRequest(endpoint, "GET", args)
}

func POST(endpoint string, args url.Values) (string, map[string]string, error) {
	return sendRequest(endpoint, "POST", args)
}

func find(data, key string) string {
	el := "name=\"" + key + "\""
	idx := strings.Index(data, el)
	if idx == -1 {
		return ""
	}
	idx += len(el)

	idx2 := strings.Index(data[idx:], "value=")
	if idx2 == -1 {
		return ""
	}
	idx += idx2 + 7 // skip value="
	end_idx := strings.Index(data[idx:], "\"")

	return data[idx : idx+end_idx]
}

// CreateCookie creates a cookie to be used by external calls to the
// Cased Shell API.
func CreateCookie() string {
	cookie := ""
	if session_id != "" {
		cookie += "session_id=" + session_id
	}

	if xsrf != "" {
		if cookie != "" {
			cookie += "; "
		}
		cookie += "_xsrf=" + xsrf
	}

	if jwt != "" {
		if cookie != "" {
			cookie += "; "
		}
		cookie += "token=" + jwt
	}

	if cs_token != "" {
		if cookie != "" {
			cookie += "; "
		}
		cookie += "cs_token=" + cs_token
	}

	return cookie
}
