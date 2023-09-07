package main

// https://github.com/projectdiscovery/subfinder/blob/main/v2/examples/main.go
// https://github.com/projectdiscovery/wappalyzergo
// https://github.com/slotix/pageres-go-wrapper
// https://github.com/chromedp/examples

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/chromedp/chromedp"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var tech string
var stackarr []string
var buf []byte

type info struct {
	url  string
	tech string
}

func addInfo(url string, tech string) *info {
	p := info{url: url, tech: tech}
	return &p
}

// ^\*\. to match .* for wildcards
func CheckError(e error, message string) {
	if e != nil {
		log.Print(message+" ", e)
	}
}
func fullScreenshot(urlstr string, quality int, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(urlstr),
		chromedp.FullScreenshot(res, quality),
	}
}
func main() {
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		// chromedp.WithDebugf(log.Printf),
	)
	defer cancel()
	thing := 0
	log.SetFlags(0)
	// fmt.Println("arglen", len(os.Args))
	if len(os.Args) == 1 {
		fmt.Println("Please supply a file")
		os.Exit(0)
	}
	err := os.Truncate("alive.txt", 0)
	CheckError(err, "Can't Truncate alive.txt; likely does not exist yet")
	content, err := os.ReadFile(os.Args[1])
	r, _ := regexp.Compile(`^\*\.`)
	fmt.Println(string(content))
	CheckError(err, "file does not exist")
	f, err := os.Create("parsed.txt")
	CheckError(err, "parsing problem")
	defer f.Close()
	_, err = f.WriteString(r.ReplaceAllString(string(content), ""))
	CheckError(err, "problem with regex")

	subfinderOpts := &runner.Options{
		Threads:            1,  // Thread controls the number of threads to use for active enumerations
		Timeout:            20, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		// ProviderConfig: "your_provider_config.yaml", need to give options to create custom
	}

	// disable timestamps in logs / configure logger

	subfinder, err := runner.NewRunner(subfinderOpts)
	CheckError(err, "Failed to create subfinder runner")

	output := &bytes.Buffer{}

	// To run subdomain enumeration on a list of domains from file/reader
	file, err := os.Open("parsed.txt")
	CheckError(err, "Can't open domain file")
	defer file.Close()
	err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), file, []io.Writer{output})
	CheckError(err, "Failed to Enumerate Subdomains from file")

	// print the output
	sd := output.String()
	log.Println(sd)
	f2, err := os.Create("subdomains.txt")
	CheckError(err, "Can't create subdomains file")
	defer f2.Close()
	_, err = f2.WriteString(sd)
	CheckError(err, "failed to write to subdomain file")

	readFile, err := os.Open("subdomains.txt")
	CheckError(err, "failed to read subdomain file")
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		text := fileScanner.Text()
		fmt.Println(text)
		resp, err := http.DefaultClient.Get(fmt.Sprintf("http://%s", text))
		if err != nil {
			if strings.Contains(err.Error(), "no such host") { //todo fix error for certs
				log.Print(err)
				log.Print("not alive, skipping")
			}
		} else {
			data, err := io.ReadAll(resp.Body) // Ignoring error for example //this breaks
			CheckError(err, "failed to read body")

			wappalyzerClient, err := wappalyzer.New()
			fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
			for key := range fingerprints {

				stackarr = append(stackarr, key)
				//	fmt.Printf(stackarr[thing])
				fmt.Printf(key + " ")
				thing++
			}
			if err := chromedp.Run(ctx, fullScreenshot(fmt.Sprintf("http://%s", text), 90, &buf)); err != nil {
				log.Fatal(err)
			}
			os.Mkdir("screenshots", 0o644)
			if err := os.WriteFile("screenshots/"+strings.Join(strings.Split(text, "."), "_")+".png", buf, 0o644); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("\n")
			f3, err := os.OpenFile("alive.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			CheckError(err, "failed to create alive.txt")
			defer f3.Close()
			info := addInfo(text, strings.Join(stackarr, ", "))
			fmt.Println(info.url, info.tech)
			_, err = f3.WriteString(text + "\n" + strings.Join(stackarr, ", ") + "\n")
			CheckError(err, "failed to write to alive.txt")
			stackarr = stackarr[:0]
			thing = 0

		}
	}
	readFile.Close()
}
