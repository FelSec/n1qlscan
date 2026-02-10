/*
Copyright © 2025 FelSec <felsec@protonmail.com>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/felsec/n1qlscan/internal/scanner"
	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"
	"github.com/spf13/cobra"
)

var (
	mUrlStr         string
	mRequestFileStr string
)

// manualCmd represents the manual command
var manualCmd = &cobra.Command{
	Use:   "manual {--url URL | --request FILE} --payload PAYLOAD --parameter PARAMETER",
	Short: "Run a custom injection attack",
	Long: `
███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                 
Run a custom N1QL injection attack against the target application.

Examples:
  URL
  n1qlscan manual -u https://vulnerableapp.com/vulnpage?param=1 -p param -P "'OR'a'='a"

  Request File
  n1qlscan manual -r ./vulnerable-request.txt -p param -P "'OR'a'='a"
`,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.NoState = true
		mUrlStr, _ = cmd.Flags().GetString("url")
		mRequestFileStr, _ = cmd.Flags().GetString("request")
		if mUrlStr == "" && mRequestFileStr == "" {
			cmd.Help()
			util.LogErr("Missing required flags.\nPlease provide a target to exploit via the url or request flag!")
			os.Exit(0)
		}
		if mUrlStr != "" && mRequestFileStr != "" {
			cmd.Help()
			util.LogErr("Error: URL and request file provided.\nPlease provide a single target to exploit via the url or request flag!")
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf(`
███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                 
`)
		currentTime := time.Now()
		cmd.Printf("Manual exploit start: %s\n", currentTime.Format("02/01/2006 15:04:05"))

		var victim target.Target
		// Set attack verbose - for logging
		// Set attack TlsSkipVerify - Skip SSL/TLS verification
		scanner.Verbose, _ = cmd.Flags().GetBool("verbose")
		scanner.TlsSkipVerify, _ = cmd.Flags().GetBool("insecure")

		// Set attack proxy
		scanner.Proxy, _ = cmd.Flags().GetString("proxy")

		switch {
		case mUrlStr != "":
			victim = target.ParseUrl(mUrlStr)
		case mRequestFileStr != "":
			victim = target.ParseReqFile(mRequestFileStr)
		}

		forceSsl, _ := cmd.Flags().GetBool("force-ssl")
		if forceSsl {
			victim.SetProtocol("https")
		}

		headers, _ := cmd.Flags().GetStringSlice("header")
		for _, header := range headers {
			if strings.Contains(header, ":") {
				h := strings.SplitN(header, ":", 2)
				victim.AddHeader(h[0], h[1])
			} else {
				util.LogErr("An invalid header was provided.\nHeaders should be in format <Header Name>:<Header Value>.\nIgnoring the provided header.")
			}
		}

		cookies, _ := cmd.Flags().GetStringSlice("cookie")
		for _, cookie := range cookies {
			if strings.Contains(cookie, "=") {
				c := strings.SplitN(cookie, "=", 2)
				victim.AddCookie(c[0], c[1])
			} else {
				util.LogErr("An invalid cookie was provided.\nCookies should be in format <Cookie Name>=<Cookie Value>.\nIgnoring the provided cookie.")
			}
		}

		// Test connection to host
		checkConnection, _ := cmd.Flags().GetBool("skip-check")
		if !checkConnection {
			util.LogInfo("Checking connection to target application")
			// Test connection
			if !scanner.CheckConnection(victim) {
				util.LogErr("Unable to reach the application.")
				return
			}
		} else {
			util.LogInfo("Skpping connection check")
		}

		// Check parameter present and where
		targetParam, _ := cmd.Flags().GetString("parameter")
		location := scanner.LocateParameter(victim, targetParam)
		if len(location) <= 0 {
			util.LogErr("Supplied parameter not found!")
			return
		}

		payload, _ := cmd.Flags().GetString("payload")
		noEncode, _ := cmd.Flags().GetBool("no-urlencode")

		switch location[0] {
		case scanner.Query:
			if noEncode {
				victim.Params[targetParam] += payload
			} else {
				victim.Params[targetParam] += url.QueryEscape(payload)
			}
		case scanner.Header:
			victim.Headers[targetParam] += payload
		case scanner.Cookie:
			victim.Cookies[targetParam] += payload
		case scanner.Body:
			switch victim.BodyType {
			case target.FORM:
				victim.Body[targetParam] = fmt.Sprintf("%v%s", victim.Body[targetParam], payload)
			case target.JSON:
				// Marshal the JSON into a string
				bJson, err := json.Marshal(victim.Body)
				if err != nil {
					util.LogErr("Unable to build JSON body")
					return
				}
				bodyString := string(bJson)
				// Find parameter "<param>":
				index := 0
				index += strings.Index(bodyString, targetParam)
				index += len(targetParam)
				index += strings.Index(bodyString[index:], ":")
				index += strings.Index(bodyString[index:], "\"")
				index += 1 // skip past index of "
				index += strings.Index(bodyString[index:], "\"")
				newBodyString := bodyString[:index] + payload + bodyString[index:]
				// Unmarshal string back into map and assign to victim
				var result map[string]any
				json.Unmarshal([]byte(newBodyString), &result)
				victim.Body = result
			}
		case scanner.Path:
			idx := slices.Index(victim.Path, targetParam)
			victim.Path[idx] = victim.Path[idx] + url.PathEscape(payload)
		default:
			util.LogErr("Supplied parameter not found!")
			return
		}

		// Run Attack
		scanner.RawAttack(victim)
	},
}

func init() {
	rootCmd.AddCommand(manualCmd)
	util.NoState = true

	manualCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Help()
		util.LogErr(err.Error())
		return nil
	})
	manualCmd.Flags().SortFlags = false
	// Flags
	manualCmd.Flags().StringP("url", "u", "", "Target URL (e.g. `https://vulnerableapp.com/vulnpage?param=1`)")
	manualCmd.Flags().StringP("request", "r", "", "Load a request from a file")
	manualCmd.MarkFlagsOneRequired("url", "request")
	manualCmd.MarkFlagsMutuallyExclusive("url", "request")

	manualCmd.Flags().StringP("parameter", "p", "", "Parameter to inject into")
	manualCmd.MarkFlagRequired("parameter")
	manualCmd.Flags().StringP("payload", "P", "", "Payload to send")
	manualCmd.MarkFlagRequired("payload")
	manualCmd.Flags().Bool("no-urlencode", false, "Prevent URL encoding of payload (You will need to encode it yourself)")
}
