package scanner

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"
)

var TlsSkipVerify bool
var Verbose bool
var Proxy string

func CheckConnection(t target.Target) bool {
	client := CreateClient()
	resp, err := DoRequest(t, client)
	if err != nil {
		return false
	}

	util.LogInfo(fmt.Sprintf("Application accessible. Response returned: %s", resp.Status))

	return true
}

func DoRequest(t target.Target, c *http.Client) (*http.Response, error) {
	bodyData := []byte(t.BodyParams())

	req, err := http.NewRequest(t.Method, t.GetUrl(), bytes.NewBuffer(bodyData))
	if err != nil {
		util.LogErr("Issue creating the HTTP Request.")
		return &http.Response{}, err
	}

	for key, value := range t.Headers {
		req.Header.Add(key, value)
	}

	for key, value := range t.Cookies {
		req.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	return c.Do(req)
}

func CreateClient() *http.Client {
	// setup proxy and HTTP client to be used across all checks
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: TlsSkipVerify}}

	if Proxy != "" {
		proxyURL, err := url.Parse(Proxy)
		if err != nil {
			util.LogErr("Invalid proxy!")
			os.Exit(-1)
		}

		httpProxy := http.ProxyURL(proxyURL)
		transport.Proxy = httpProxy
	}

	client.Transport = transport
	return client
}
