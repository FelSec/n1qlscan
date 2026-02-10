//go:build windows

package state

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"
)

var folderName string = "n1qlscan"

var (
	Domain string
	Path   string
	Method string
)

func GetBasePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		util.LogErr("Unable to get home Directory")
	}
	homeDir = filepath.Join(homeDir, "AppData")
	homeDir = filepath.Join(homeDir, "Roaming")

	return filepath.Join(homeDir, folderName)
}

func FolderExists(folder string) bool {
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return false
	}
	return true
}

func CreateFolder(folder string) {
	err := os.MkdirAll(folder, 0700)
	if err != nil {
		util.LogErr(fmt.Sprintf("Unable to create folder: %s", folder))
	}
}

func CheckNscanFolder() {
	nscanDir := GetBasePath()
	if !FolderExists(nscanDir) {
		CreateFolder(nscanDir)
	}
}

func GetProjectFolder() string {
	return filepath.Join(GetBasePath(),
		strings.ReplaceAll(Domain, ":", "_"),
		strings.ReplaceAll(Path, ":", "_"),
		Method)
}

func CreateScanFolder() {
	nscanDir := GetBasePath()
	CheckNscanFolder()

	nscanDir = filepath.Join(nscanDir, strings.ReplaceAll(Domain, ":", "_"))
	if !FolderExists(nscanDir) {
		CreateFolder(nscanDir)
	}

	nscanDir = filepath.Join(nscanDir, strings.ReplaceAll(Path, ":", "_"))
	if !FolderExists(nscanDir) {
		CreateFolder(nscanDir)
	}

	nscanDir = filepath.Join(nscanDir, Method)
	if !FolderExists(nscanDir) {
		CreateFolder(nscanDir)
	}

	// Scan folder - .n1qlscan/<domain>/<path - replace / with :>/<METHOD>/
	// scan files - <timstamp - YYYYMMDD-HHMMSS>-log.log
	// 						- dump.log
	// 						- vulnerable.bson - vulnerable parameters
	// 						- scaninfo.txt - scan information

	// vulnerable file:
	// serialised data - <id>:<vulnerable>:<TBD - BSON>
}

func CreateScanInfoFile(t *target.Target) {
	targetFilePath := filepath.Join(GetProjectFolder(), "scaninfo.txt")

	// Scan Info
	// Domain: <domain>
	// Protocol: <HTTP,HTTPS>
	// Method: <>
	// Path: <path>
	// Headers: <>
	// Cookies: <>
	// BodyType: <>
	// Body: <>
	// Query Parameters: <>

	scanInfo := ""
	scanInfo += fmt.Sprintf("Domain: %s\n", t.Domain)
	scanInfo += fmt.Sprintf("Protocol: %s\n", t.Protocol)
	scanInfo += fmt.Sprintf("Method: %s\n", t.Method)
	scanInfo += fmt.Sprintf("Path: /%s\n", strings.Join(t.Path, "/"))
	scanInfo += "Headers:\n"
	for k, v := range t.Headers {
		scanInfo += fmt.Sprintf("+ %s: %s\n", k, v)
	}
	scanInfo += "Cookies:\n"
	for k, v := range t.Cookies {
		scanInfo += fmt.Sprintf("+ %s=%s\n", k, v)
	}
	if t.BodyType != target.NONE {
		switch t.BodyType {
		case target.FORM:
			scanInfo += "Body Type: Form\n"
		case target.JSON:
			scanInfo += "Body Type: json\n"
		case target.MISC:
			scanInfo += "Body Type: Misc\n"
		}
		scanInfo += fmt.Sprintf("Body:\n%s\n", t.BodyParams())
	}
	if len(t.Params) > 0 {
		scanInfo += "Query Parameters:\n"
		for k, v := range t.Params {
			scanInfo += fmt.Sprintf("+ %s=%s\n", k, v)
		}
	}

	if err := os.WriteFile(targetFilePath, []byte(scanInfo), 0644); err != nil {
		util.LogErr(fmt.Sprintf("Unable to write target file: %s", err))
	}
}

func WriteVulnData(vulndata []target.Vulnerable) {
	targetFilePath := filepath.Join(GetProjectFolder(), "vulnerable.data")

	f, err := os.OpenFile(targetFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		util.LogErr(fmt.Sprintf("Unable to create or open vulnerable endpoints file: %s", err))
		return
	}

	defer f.Close()

	for index, data := range vulndata {
		if _, err := fmt.Fprintf(f, "%d:%s", (index + 1), data.Serialize()); err != nil {
			util.LogErr("Unable to write vulnerable endpoint data to file")
			return
		}
	}
}

func ReadVulnData() []string {
	targetFilePath := filepath.Join(GetProjectFolder(), "vulnerable.data")

	var data []string

	f, err := os.OpenFile(targetFilePath, os.O_RDONLY, 0644)
	if err != nil {
		util.LogErr(fmt.Sprintf("Unable to create or open vulnerable endpoints file: %s", err))
		return data
	}

	defer f.Close()

	s := bufio.NewScanner(f)

	for s.Scan() {
		data = append(data, s.Text())
	}

	return data

}
