package scanner

import (
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/felsec/n1qlscan/internal/target"
)

func CompareResponses(baseStatusCode int, baseRawBody string, check *http.Response, currentPayload string) bool {
	if baseStatusCode != check.StatusCode {
		return false
	}
	defer check.Body.Close()
	checkBodyBytes, _ := io.ReadAll(check.Body)
	checkRawBody := string(checkBodyBytes)
	checkBody := html.UnescapeString(checkRawBody)
	if !strings.Contains(checkBody, currentPayload) {
		if baseRawBody != checkRawBody {
			return false
		}
	}
	return true
}

func UpdateResults(currentResults []target.Vulnerable, newVulnerable []target.Vulnerable) []target.Vulnerable {
	if 1 > len(newVulnerable) {
		return currentResults
	}

	if 1 > len(currentResults) {
		return append(currentResults, newVulnerable[0])
	}

	for _, r := range currentResults {
		if newVulnerable[0].Parameter == r.Parameter {
			if newVulnerable[0].ExploitType == r.ExploitType {
				if strings.Contains(newVulnerable[0].PayloadTemplate, r.PayloadTemplate) && !strings.HasSuffix(newVulnerable[0].PayloadTemplate, "--") {
					return currentResults
				}
			}
		}
	}

	return append(currentResults, newVulnerable[0])
}
