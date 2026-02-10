package target

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Scheme int

const (
	HTTP Scheme = iota
	HTTPS
)

var schemeName = map[Scheme]string{
	HTTP:  "HTTP",
	HTTPS: "HTTPS",
}

func (s Scheme) String() string {
	return schemeName[s]
}

type BodyType int

const (
	NONE BodyType = iota
	JSON
	FORM
	MISC
)

type Target struct {
	Domain   string
	Protocol Scheme
	Path     []string
	Params   map[string]string
	Headers  map[string]string
	Cookies  map[string]string
	Method   string
	Body     map[string]any
	BodyType BodyType
}

func (target *Target) SetProtocol(scheme string) {
	switch strings.ToLower(scheme) {
	case "http":
		target.Protocol = HTTP
	default:
		target.Protocol = HTTPS
	}
}

func (target *Target) AddCookie(key string, value string) {
	if target.Cookies == nil {
		target.Cookies = make(map[string]string)
	}
	target.Cookies[key] = value
}

func (target *Target) AddHeader(key string, value string) {
	if target.Headers == nil {
		target.Headers = make(map[string]string)
	}
	target.Headers[key] = value
}

func ParseUrl(urlStr string) Target {
	target := Target{}

	// Use Golang's built-in URL library to parse the string
	u, err := url.Parse(urlStr)
	if err != nil {
		return target
	}

	// Map the URL output to the target fields
	// Note: some of these fields may get overwritten by application flags
	target.Domain = u.Host

	target.SetProtocol(u.Scheme)

	target.Path = strings.Split(strings.TrimPrefix(u.Path, "/"), "/")

	target.Params = make(map[string]string)

	for key, value := range u.Query() {
		target.Params[key] = value[0]
	}

	target.Method = "GET"

	target.BodyType = NONE

	return target
}

func ParseReqFile(filePath string) Target {
	target := Target{}
	target.SetProtocol("HTTP")

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error: Failed to read file: %s", err)
	}

	lines := strings.Split(string(data), "\n")

	header_finished := false

	body_lines := ""
	for idx, line := range lines {
		if idx == 0 {
			parts := strings.Split(line, " ")
			fmt.Printf("Method: %s\n", parts[0])
			target.Method = parts[0]
			fmt.Printf("Path: %s\n", parts[1])
			if strings.Contains(parts[1], "?") {
				// split on ? character
				pq := strings.Split(parts[1], "?")
				// process path parts
				target.Path = strings.Split(strings.TrimPrefix(pq[0], "/"), "/")
				target.Params = make(map[string]string)

				for query := range strings.SplitSeq(pq[1], "&") {
					key, value, _ := strings.Cut(query, "=")
					target.Params[key] = value
				}
			} else {
				target.Path = strings.Split(strings.TrimPrefix(parts[1], "/"), "/")
			}
			continue
		}
		if !header_finished {
			// Check for host header
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				_, host, _ := strings.Cut(line, ":")
				target.Domain = strings.TrimSpace(host)
				continue
			}
			// Check for cookies
			if strings.HasPrefix(strings.ToLower(line), "cookie:") {
				_, cookies, _ := strings.Cut(line, ":")
				for kv := range strings.SplitSeq(strings.TrimSpace(cookies), ";") {
					key, value, _ := strings.Cut(kv, "=")
					target.AddCookie(key, value)
				}
				continue
			}
			if strings.HasPrefix(line, "Content-Length:") {
				continue
			}
			if strings.HasPrefix(line, "Content-Type:") {
				key, value, _ := strings.Cut(line, ":")
				target.AddHeader(key, strings.TrimSpace(value))
				switch {
				case strings.Contains(value, "json"):
					target.BodyType = JSON
					target.Body = make(map[string]any)
				case strings.Contains(value, "x-www-form-urlencoded"):
					target.BodyType = FORM
					target.Body = make(map[string]any)
				case strings.Contains(value, "form-data"):
					fmt.Printf("[ERROR] Multipart Form Data is not currently supported!")
					target.BodyType = NONE
				default:
					target.BodyType = MISC
					target.Body = make(map[string]any)
				}
				continue
			}
			if line == "\n" || line == "\r" || line == "" {
				header_finished = true
				continue
			}
			key, value, _ := strings.Cut(line, ":")
			target.AddHeader(key, strings.TrimSpace(value))
		} else {
			if line != "" {
				body_lines += line
			}
		}
	}

	switch target.BodyType {
	case FORM:
		for param := range strings.SplitSeq(body_lines, "&") {
			key, value, _ := strings.Cut(param, "=")
			target.Body[key] = value
		}
	case JSON:
		var result map[string]any
		json.Unmarshal([]byte(body_lines), &result)
		target.Body = result
	default:
		fmt.Printf("[DEBUG] Not implemented yet\n")
	}

	return target
}

func (target *Target) GetUrl() string {
	queryStr := target.QueryParams()

	var fullUrl string = ""
	fullUrl += strings.ToLower(target.Protocol.String())
	fullUrl += "://"
	fullUrl += target.Domain
	fullUrl += "/"
	fullUrl += strings.Join(target.Path, "/")

	if queryStr != "" {
		fullUrl += "?"
		fullUrl += queryStr
	}

	return fullUrl
}

func (target *Target) QueryParams() string {
	var queryStrs []string
	for key, value := range target.Params {
		queryStrs = append(queryStrs, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(queryStrs, "&")
}

func (target *Target) BodyParams() string {
	switch target.BodyType {
	case FORM:
		var bodyStrs []string
		for key, value := range target.Body {
			bodyStrs = append(bodyStrs, fmt.Sprintf("%s=%s", key, value))
		}
		return strings.Join(bodyStrs, "&")
	case JSON:
		bodyJson, err := json.Marshal(target.Body)
		if err != nil {
			fmt.Printf("Error: Error building JSON body\n")
			bodyJson = []byte("{}")
		}
		return string(bodyJson)
	default:
		return ""
	}
}

func (target *Target) BuildJsonPayloads(base map[string]any) map[string]string {
	payloadList := make(map[string]string)

	placeholder := "[payloadpoint]"

	bodyJson, err := json.Marshal(base)
	if err != nil {
		fmt.Printf("Error: Unable to build JSON body\n")
		return payloadList
	}
	bodyStr := string(bodyJson)

	match := regexp.MustCompile("(:|\\[|,)[^:}\\[\\],]+(,|}|])")
	match2 := regexp.MustCompile("(,)[^:}\\],]+(,|])")
	locs := match.FindAllIndex([]byte(bodyStr), -1)
	locs2 := match2.FindAllIndex([]byte(bodyStr), -1)

	fullList := append(locs, locs2...)
	fullList = MergeSort(fullList)

	dup := 1

	for _, p := range fullList {
		// get key based on regex loc
		keyIndexEnd := strings.LastIndex(bodyStr[:p[0]+1], "\":")
		KeyIndexStart := strings.LastIndex(bodyStr[:keyIndexEnd], "\"")
		key := bodyStr[KeyIndexStart+1 : keyIndexEnd]

		// Create payload
		value := ""
		if strings.Contains(bodyStr[p[0]+1:p[1]-1], "\"") {
			value = bodyStr[p[0]+2 : p[1]-2]
		} else {
			value = bodyStr[p[0]+1 : p[1]-1]
		}
		payload := fmt.Sprintf("%s\"%s%s\"%s", bodyStr[:p[0]+1], value, placeholder, bodyStr[p[1]-1:])
		if _, ok := payloadList[key]; ok {
			key = fmt.Sprintf("%s#@%d", key, dup)
		}
		payloadList[key] = payload
	}

	return payloadList
}

func MergeSort(items [][]int) [][]int {
	if len(items) < 2 {
		return items
	}

	first := MergeSort(items[:len(items)/2])
	second := MergeSort(items[len(items)/2:])

	return Merge(first, second)
}

func Merge(a, b [][]int) [][]int {
	final := [][]int{}
	i := 0
	j := 0
	for i < len(a) && j < len(b) {
		if a[i][0] < b[j][0] {
			final = append(final, a[i])
			i++
		} else {
			final = append(final, b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		final = append(final, a[i])
	}
	for ; j < len(b); j++ {
		final = append(final, b[j])
	}
	return final
}

func (target *Target) Copy() Target {
	var newTarget Target
	data, _ := json.Marshal(target)
	json.Unmarshal(data, &newTarget)
	return newTarget
}
