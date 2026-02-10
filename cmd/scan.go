/*
Copyright © 2025 FelSec <felsec@protonmail.com>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/felsec/n1qlscan/internal/scanner"
	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"
	"github.com/felsec/n1qlscan/internal/util/state"
	"github.com/spf13/cobra"
)

var (
	urlStr         string
	requestFileStr string
	victim         target.Target

	NoState bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan {--url URL | --request FILE}",
	Short: "Scan the target",
	Long: `
███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                 
Scan the target for N1QL injection vulnerabilities.

Examples:
  Scan URL
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1

  Scan using request file
  n1qlscan scan -r ./vulnerable-request.txt

  Scan a parameter
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1&id=2&search=test -p search
  
  Scan multiple parameters
  n1qlscan scan -u https://vulnerableapp.com/vulnpage?param=1&id=2&search=test -p search,id
`,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.NoState = true
		urlStr, _ = cmd.Flags().GetString("url")
		requestFileStr, _ = cmd.Flags().GetString("request")
		if urlStr == "" && requestFileStr == "" {
			cmd.Help()
			util.LogErr("Missing required flags.\nPlease provide a target to scan via the url or request flag!")
			os.Exit(0)
		}
		if urlStr != "" && requestFileStr != "" {
			cmd.Help()
			util.LogErr("Error: URL and request file provided.\nPlease provide a single target to scan via the url or request flag!")
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
		cmd.Printf("Scan start: %s\n", currentTime.Format("02/01/2006 15:04:05"))

		util.LogDate = currentTime.Format("20060102150405")

		var victim target.Target
		scanner.Verbose, _ = cmd.Flags().GetBool("verbose")
		scanner.TlsSkipVerify, _ = cmd.Flags().GetBool("insecure")
		NoState, _ = cmd.Flags().GetBool("no-state")
		util.NoState = NoState

		scanner.Proxy, _ = cmd.Flags().GetString("proxy")

		switch {
		case urlStr != "":
			victim = target.ParseUrl(urlStr)
		case requestFileStr != "":
			victim = target.ParseReqFile(requestFileStr)
		}

		state.Domain = victim.Domain
		state.Method = victim.Method
		state.Path = strings.Join(victim.Path, ":")
		util.ProjectPath = state.GetProjectFolder()

		if !NoState {
			state.CreateScanFolder()
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

		inc, _ := cmd.Flags().GetStringSlice("parameter")
		var paramLocation [5]bool
		for _, p := range inc {
			for _, m := range scanner.LocateParameter(victim, p) {
				paramLocation[m] = true
			}
		}

		if len(inc) > 0 && allFalse(paramLocation[:]) {
			util.LogErr("Supplied parameter(s) not found!")
			return
		}

		exc, _ := cmd.Flags().GetStringSlice("exclude-parameter")

		if allFalse(paramLocation[:]) {
			if victim.Params != nil {
				paramLocation[scanner.Query] = true
			} else {
				paramLocation[scanner.Query] = false
			}
			if victim.Body != nil {
				paramLocation[scanner.Body] = true
			} else {
				paramLocation[scanner.Body] = false
			}
			paramLocation[scanner.Header] = true
			if victim.Cookies != nil {
				paramLocation[scanner.Cookie] = true
			} else {
				paramLocation[scanner.Cookie] = false
			}
			if skipPath, _ := cmd.Flags().GetBool("ignore-path"); !skipPath {
				paramLocation[scanner.Path] = true
			}
		}

		if !NoState {
			state.CreateScanInfoFile(&victim)
		}

		var results []target.Vulnerable
		for idx, check := range paramLocation {
			if check {
				results = append(results, scanner.Check(victim, scanner.Mode(idx), inc, exc)...)
			}
		}
		if !NoState {
			state.WriteVulnData(results)
		}
		fmt.Println("")
		separator := "+============================================================+\n\n"
		fmt.Print(separator)
		util.LogVulnerable(separator)
		for _, result := range results {
			vMsg := fmt.Sprintf("%s\n", result)
			util.LogVulnerable(vMsg)
			fmt.Print(vMsg)
			fmt.Print(separator)
			util.LogVulnerable(separator)
		}
	},
}

func allFalse(slice []bool) bool {
	for i := 1; i < len(slice); i++ {
		if slice[i] != slice[0] {
			return false
		}
	}
	return true
}

func init() {
	rootCmd.AddCommand(scanCmd)

	util.NoState = true
	scanCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Help()
		util.LogErr(err.Error())
		return nil
	})

	state.CheckNscanFolder()

	scanCmd.Flags().SortFlags = false
	// Flags
	scanCmd.Flags().StringP("url", "u", "", "Target URL to scan (e.g. `https://vulnerableapp.com/vulnpage?param=1`)")
	scanCmd.Flags().StringP("request", "r", "", "Load a request from a file for scanning")
	scanCmd.MarkFlagsOneRequired("url", "request")
	scanCmd.MarkFlagsMutuallyExclusive("url", "request")

	scanCmd.Flags().StringSliceP("parameter", "p", []string{}, "Parameter(s) to test - e.g. -p `param1,param2`")
	scanCmd.Flags().StringSlice("exclude-parameter", []string{}, "Parameter(s) to exclude from testing - e.g. --exclude-parameter `param3,param4`")
	scanCmd.Flags().Bool("ignore-path", false, "Don't scan the URL path")
}
