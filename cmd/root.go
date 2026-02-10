/*
Copyright © 2025 FelSec <felsec@protonmail.com>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "n1qlscan",
	Short: "N1QLScan - Automated N1QL Injection Tool",
	Long: `
███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                 
Automated N1QL injection scanning and exploitation tool`,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose")
	rootCmd.PersistentFlags().Bool("no-state", false, "No-State")

	rootCmd.PersistentFlags().StringSliceP("header", "H", []string{}, "Add a custom header to the request, in the format `<header>:<value>` - e.g. X-Custom-Header:ThisIsACustomHeader")
	rootCmd.PersistentFlags().StringSliceP("cookie", "C", []string{}, "Add a cookie to the request, in the format `<cookie name>=<cookie value>` - e.g. session=ThisIsACookie")

	rootCmd.PersistentFlags().BoolP("insecure", "k", false, "Disable TLS certificate validation")
	rootCmd.PersistentFlags().Bool("force-ssl", false, "Force the use of SSL/HTTPS")
	rootCmd.PersistentFlags().Bool("skip-check", false, "Skip checking connection to the target")
	rootCmd.PersistentFlags().StringP("proxy", "", "", "Use a proxy to connect to the target `http://<proxy>:<port>` - e.g. http://127.0.0.1:8080")
}
