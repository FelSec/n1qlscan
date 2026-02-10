/*
Copyright © 2025 FelSec <felsec@protonmail.com>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the current version information",
	Run: func(cmd *cobra.Command, args []string) {
		versionMessage := `
███╗   ██╗ ██╗ ██████╗ ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║███║██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║╚██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║ ██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║ ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                 
version 0.0.1`
		fmt.Println(versionMessage)
	},
	DisableFlagsInUseLine: true,
	DisableFlagParsing:    true,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
