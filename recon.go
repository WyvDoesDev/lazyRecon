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

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// ^\*\. to match .* for wildcards
func main() {
	if err := os.Truncate("alive.txt", 0); err != nil {
		log.Printf("Failed to truncate: %v", err)
	}
	// fmt.Println("arglen", len(os.Args))
	if len(os.Args) == 1 {
		fmt.Println("Please supply a file")
		os.Exit(0)
	} else {
		content, err := os.ReadFile(os.Args[1])
		r, _ := regexp.Compile(`^\*\.`)
		fmt.Println(string(content))
		if err != nil {
			log.Print(err)
			fmt.Println("Please supply a file that exists")
		}
		f, err := os.Create("parsed.txt")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		_, err2 := f.WriteString(r.ReplaceAllString(string(content), ""))
		if err2 != nil {
			log.Fatal(err2)
		}

		subfinderOpts := &runner.Options{
			Threads:            1,  // Thread controls the number of threads to use for active enumerations
			Timeout:            20, // Timeout is the seconds to wait for sources to respond
			MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
			// ProviderConfig: "your_provider_config.yaml", need to give options to create custom
		}

		// disable timestamps in logs / configure logger
		log.SetFlags(0)

		subfinder, err := runner.NewRunner(subfinderOpts)
		if err != nil {
			log.Fatalf("failed to create subfinder runner: %v", err)
		}

		output := &bytes.Buffer{}

		// To run subdomain enumeration on a list of domains from file/reader
		file, err := os.Open("parsed.txt")
		if err != nil {
			log.Fatalf("failed to open domains file: %v", err)
		}
		defer file.Close()
		if err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), file, []io.Writer{output}); err != nil {
			log.Fatalf("failed to enumerate subdomains from file: %v", err)
		}

		// print the output
		sd := output.String()
		log.Println(sd)
		f2, err := os.Create("subdomains.txt")
		if err != nil {
			log.Fatal(err)
		}
		defer f2.Close()
		_, err3 := f2.WriteString(sd)
		if err3 != nil {
			log.Fatal(err3)
		}

		readFile, err := os.Open("subdomains.txt")

		if err != nil {
			fmt.Println(err)
		}
		fileScanner := bufio.NewScanner(readFile)

		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			text := fileScanner.Text()
			fmt.Println(text)
			_, err := http.Get(fmt.Sprintf("http://%s", text))
			if err != nil {
				log.Print("not alive, skipping")
			} else {
				f3, err := os.OpenFile("alive.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Fatal(err)
				}
				defer f3.Close()
				_, err4 := f3.WriteString(text + "\n")
				if err4 != nil {
					log.Fatal(err4)
				}
			}
		}

		readFile.Close()
	}

}
