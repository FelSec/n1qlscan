package scanner

import (
	"encoding/json"
	"fmt"
	//"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/felsec/n1qlscan/internal/payloads"
	"github.com/felsec/n1qlscan/internal/target"
	"github.com/felsec/n1qlscan/internal/util"

	"github.com/lithammer/fuzzysearch/fuzzy"
)

type Mode int

const (
	Query Mode = iota
	Body
	Header
	Cookie
	Path
)

func Check(t target.Target, mode Mode, include []string, exclude []string) []target.Vulnerable {
	// setup proxy and HTTP client to be used across all checks
	client := CreateClient()
	// create copy of target
	targetTest := t
	// setup results slice
	var results []target.Vulnerable
	// perform checks
	switch mode {
	case Query:
		// loap over each query parameter
		for key, value := range targetTest.Params {

			if (len(include) > 0 && !slices.Contains(include, key)) || (len(exclude) > 0 && slices.Contains(exclude, key)) {
				util.LogInfo(fmt.Sprintf("Skipping checks for parameter: %s", key))
				continue
			}
			util.LogInfo(fmt.Sprintf("Testing Get parameter %s", key))
			// perform base request for comparisons
			targetTest.Params[key] = value + "_N1QLSCAN"

			bcode, bbody, err := GetComparisonData(targetTest, client)
			if err != nil {
				util.LogErr(err.Error())
				return results
			}
			var checkList []int
			// loop over payloads and test for potential vulnerabilities
			for pos, payload := range payloads.EntryPoints {
				// modify target parameter
				targetTest.Params[key] = value + payload
				// send request
				ccode, cbody, err := GetComparisonData(t, client)
				if err != nil {
					util.LogErr(err.Error())
					targetTest.Params[key] = value
					return results
				}
				if ccode != bcode ||
					cbody != bbody {
					checkList = append(checkList, pos)
				}
			}
			if 1 > len(checkList) {
				targetTest.Params[key] = value
				continue
			}
			util.LogInfo("Performing Boolean-based AND checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanAndCheck(targetTest, client, pos, value, key, target.VQUERY))
			}
			util.LogInfo("Performing Boolean-based OR checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanOrCheck(targetTest, client, pos, value, key, target.VQUERY))
			}
			util.LogInfo("Performing Union checks")
			for _, pos := range checkList {
				results = UpdateResults(results, UnionCheck(targetTest, client, pos, value, key, target.VQUERY))
			}
			util.LogInfo("Performing Stacked Query checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StackedQueryCheck(targetTest, client, pos, value, key, target.VQUERY))
			}
			util.LogInfo("Performing String Concatenation checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StringConcatCheck(targetTest, client, pos, value, key, target.VQUERY))
			}
			util.LogInfo("Performing Error-based checks")
			for _, pos := range checkList {
				results = UpdateResults(results, ErrorCheck(targetTest, client, pos, value, key, target.VQUERY))
			}

			//reset parameter
			targetTest.Params[key] = value
		}
	case Header:
		for key, value := range targetTest.Headers {
			if (len(include) > 0 && !slices.Contains(include, key)) || (len(exclude) > 0 && slices.Contains(exclude, key)) {
				util.LogInfo(fmt.Sprintf("Skipping checks for parameter: %s", key))
				continue
			}
			util.LogInfo(fmt.Sprintf("Testing Header %s", key))
			// perform base request for comparisons
			targetTest.Headers[key] = value + "_N1QLSCAN"

			bcode, bbody, err := GetComparisonData(targetTest, client)
			if err != nil {
				util.LogErr(err.Error())
				return results
			}
			var checkList []int
			// loop over payloads and test for potential vulnerabilities
			for pos, payload := range payloads.EntryPoints {
				// modify target parameter
				targetTest.Headers[key] = value + payload
				// send request
				ccode, cbody, err := GetComparisonData(t, client)
				if err != nil {
					util.LogErr(err.Error())
					targetTest.Headers[key] = value
					return results
				}
				if ccode != bcode ||
					cbody != bbody {
					checkList = append(checkList, pos)
				}
			}
			if 1 > len(checkList) {
				targetTest.Headers[key] = value
				continue
			}
			util.LogInfo("Performing Boolean-based AND checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanAndCheck(targetTest, client, pos, value, key, target.VHEADER))
			}
			util.LogInfo("Performing Boolean-based OR checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanOrCheck(targetTest, client, pos, value, key, target.VHEADER))
			}
			util.LogInfo("Performing Union checks")
			for _, pos := range checkList {
				results = UpdateResults(results, UnionCheck(targetTest, client, pos, value, key, target.VHEADER))
			}
			util.LogInfo("Performing Stacked Query checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StackedQueryCheck(targetTest, client, pos, value, key, target.VHEADER))
			}
			util.LogInfo("Performing String Concatenation checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StringConcatCheck(targetTest, client, pos, value, key, target.VHEADER))
			}
			util.LogInfo("Performing Error-based checks")
			for _, pos := range checkList {
				results = UpdateResults(results, ErrorCheck(targetTest, client, pos, value, key, target.VHEADER))
			}

			//reset parameter
			targetTest.Headers[key] = value
		}
	case Cookie:
		for key, value := range targetTest.Cookies {
			if (len(include) > 0 && !slices.Contains(include, key)) || (len(exclude) > 0 && slices.Contains(exclude, key)) {
				util.LogInfo(fmt.Sprintf("Skipping checks for parameter: %s", key))
				continue
			}
			util.LogInfo(fmt.Sprintf("Testing Cookie %s", key))
			// perform base request for comparisons
			targetTest.Cookies[key] = value + "_N1QLSCAN"

			bcode, bbody, err := GetComparisonData(targetTest, client)
			if err != nil {
				util.LogErr(err.Error())
				return results
			}
			var checkList []int
			// loop over payloads and test for potential vulnerabilities
			for pos, payload := range payloads.EntryPoints {
				// modify target parameter
				targetTest.Cookies[key] = value + payload
				// send request
				ccode, cbody, err := GetComparisonData(t, client)
				if err != nil {
					util.LogErr(err.Error())
					targetTest.Cookies[key] = value
					return results
				}
				if ccode != bcode ||
					cbody != bbody {
					checkList = append(checkList, pos)
				}
			}
			if 1 > len(checkList) {
				targetTest.Cookies[key] = value
				continue
			}
			util.LogInfo("Performing Boolean-based AND checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanAndCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			util.LogInfo("Performing Boolean-based OR checks")
			for _, pos := range checkList {
				results = UpdateResults(results, BooleanOrCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			util.LogInfo("Performing Union checks")
			for _, pos := range checkList {
				results = UpdateResults(results, UnionCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			util.LogInfo("Performing Stacked Query checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StackedQueryCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			util.LogInfo("Performing String Concatenation checks")
			for _, pos := range checkList {
				results = UpdateResults(results, StringConcatCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			util.LogInfo("Performing Error-based checks")
			for _, pos := range checkList {
				results = UpdateResults(results, ErrorCheck(targetTest, client, pos, value, key, target.VCOOKIE))
			}
			//reset parameter
			targetTest.Cookies[key] = value
		}
	case Body:
		if t.BodyType == target.JSON {
			payloadList := t.BuildJsonPayloads(t.Body)

			baseBody := t.Body

			for k, v := range payloadList {
				key := k
				if strings.Contains(k, "#@") {
					key = k[:strings.Index(k, "#@")]
				}
				if (len(include) > 0 && !slices.Contains(include, key)) || (len(exclude) > 0 && slices.Contains(exclude, key)) {
					util.LogInfo(fmt.Sprintf("Skipping checks for parameter: %s", key))
					continue
				}
				util.LogInfo(fmt.Sprintf("Testing Body parameter %s", key))

				test := strings.Replace(v, "[payloadpoint]", "_N1QLSCAN", 1)

				var result map[string]any
				json.Unmarshal([]byte(test), &result)

				targetTest.Body = result

				bcode, bbody, err := GetComparisonData(targetTest, client)
				if err != nil {
					util.LogErr(err.Error())
					targetTest.Body = baseBody
				}
				var checkList []int

				for pos, payload := range payloads.EntryPoints {
					if strings.Contains(payload, "\"") {
						payload = "\\" + payload
					}
					test := strings.Replace(v, "[payloadpoint]", payload, 1)

					var result map[string]any
					json.Unmarshal([]byte(test), &result)

					targetTest.Body = result

					ccode, cbody, err := GetComparisonData(targetTest, client)
					if err != nil {
						util.LogErr(err.Error())
						targetTest.Body = baseBody
					}

					if ccode != bcode ||
						cbody != bbody {
						checkList = append(checkList, pos)
					}
				}
				if 1 > len(checkList) {
					targetTest.Body = baseBody
					continue
				}
				util.LogInfo("Performing Boolean-based AND checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonBooleanAndCheck(targetTest, client, pos, v, key))
				}
				util.LogInfo("Performing Boolean-based OR checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonBooleanOrCheck(targetTest, client, pos, v, key))
				}
				util.LogInfo("Performing Union checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonUnionCheck(targetTest, client, pos, v, key))
				}
				util.LogInfo("Performing Stacked Query checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonStackedQueryCheck(targetTest, client, pos, v, key))
				}
				util.LogInfo("Performing String Concatenation checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonStringConcatCheck(targetTest, client, pos, v, key))
				}
				util.LogInfo("Performing Error-based checks")
				for _, pos := range checkList {
					results = UpdateResults(results, JsonErrorCheck(targetTest, client, pos, v, key))
				}

				targetTest.Body = baseBody
			}
		} else {
			for key, value := range targetTest.Body {
				if (len(include) > 0 && !slices.Contains(include, key)) || (len(exclude) > 0 && slices.Contains(exclude, key)) {
					util.LogInfo(fmt.Sprintf("Skipping checks for parameter: %s", key))
					continue
				}
				util.LogInfo(fmt.Sprintf("Testing Body parameter %s", key))

				param := fmt.Sprintf("%v", value)
				// perform base request for comparisons
				targetTest.Body[key] = param + "_N1QLSCAN"

				bcode, bbody, err := GetComparisonData(targetTest, client)
				if err != nil {
					util.LogErr(err.Error())
					return results
				}
				var checkList []int
				// loop over payloads and test for potential vulnerabilities
				for pos, payload := range payloads.EntryPoints {
					// modify target parameter
					targetTest.Body[key] = param + payload
					// send request
					ccode, cbody, err := GetComparisonData(t, client)
					if err != nil {
						util.LogErr(err.Error())
						targetTest.Body[key] = value
						return results
					}
					if ccode != bcode ||
						cbody != bbody {
						checkList = append(checkList, pos)
					}
				}
				if 1 > len(checkList) {
					targetTest.Body[key] = value
					continue
				}
				util.LogInfo("Performing Boolean-based AND checks")
				for _, pos := range checkList {
					results = UpdateResults(results, BooleanAndCheck(targetTest, client, pos, param, key, target.VBODY))
				}
				util.LogInfo("Performing Boolean-based OR checks")
				for _, pos := range checkList {
					results = UpdateResults(results, BooleanOrCheck(targetTest, client, pos, param, key, target.VBODY))
				}
				util.LogInfo("Performing Union checks")
				for _, pos := range checkList {
					results = UpdateResults(results, UnionCheck(targetTest, client, pos, param, key, target.VBODY))
				}
				util.LogInfo("Performing Stacked Query checks")
				for _, pos := range checkList {
					results = UpdateResults(results, StackedQueryCheck(targetTest, client, pos, param, key, target.VBODY))
				}
				util.LogInfo("Performing String Concatenation checks")
				for _, pos := range checkList {
					results = UpdateResults(results, StringConcatCheck(targetTest, client, pos, param, key, target.VBODY))
				}
				util.LogInfo("Performing Error-based checks")
				for _, pos := range checkList {
					results = UpdateResults(results, ErrorCheck(targetTest, client, pos, param, key, target.VBODY))
				}

				//reset parameter
				targetTest.Body[key] = value
			}
		}
	case Path:
		for idx, section := range targetTest.Path {
			util.LogInfo(fmt.Sprintf("Testing path segment %s", section))
			// perform base request for comparisons
			targetTest.Path[idx] = section + "_N1QLSCAN"

			bcode, bbody, err := GetComparisonData(targetTest, client)
			if err != nil {
				util.LogErr(err.Error())
				return results
			}
			var checkList []int
			// loop over payloads and test for potential vulnerabilities
			for pos, payload := range payloads.EntryPoints {
				// modify target parameter
				targetTest.Path[idx] = section + payload
				// send request
				ccode, cbody, err := GetComparisonData(t, client)
				if err != nil {
					util.LogErr(err.Error())
					targetTest.Path[idx] = section
					return results
				}
				if ccode != bcode ||
					cbody != bbody {
					checkList = append(checkList, pos)
				}
			}
			if 1 > len(checkList) {
				targetTest.Path[idx] = section
				continue
			}
			util.LogInfo("Performing Boolean-based AND checks")
			for _, pos := range checkList {
				output := BooleanAndCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}
			util.LogInfo("Performing Boolean-based OR checks")
			for _, pos := range checkList {
				output := BooleanOrCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}
			util.LogInfo("Performing Union checks")
			for _, pos := range checkList {
				output := UnionCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}
			util.LogInfo("Performing Stacked Query checks")
			for _, pos := range checkList {
				output := StackedQueryCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}
			util.LogInfo("Performing String Concatenation checks")
			for _, pos := range checkList {
				output := StringConcatCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}
			util.LogInfo("Performing Error-based checks")
			for _, pos := range checkList {
				output := ErrorCheck(targetTest, client, pos, section, strconv.Itoa(idx), target.VPATH)
				if 0 < len(output) {
					results = UpdateResults(results, output)
					break
				}
			}

			//reset parameter
			targetTest.Path[idx] = section
		}
	default:
		return results
	}
	return results
}

func BooleanAndCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	boolCheckAndTrue := payloads.BuildBoolPayloadSet(detection, true, true)
	boolCheckAndFalse := payloads.BuildBoolPayloadSet(detection, true, false)

	var scode int
	var sbody string
	var fcode int
	var fbody string
	var err error
	var pos int
	if l == target.VPATH {
		pos, _ = strconv.Atoi(key)
	}

	for idx := range len(boolCheckAndTrue) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", boolCheckAndTrue[idx]))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, boolCheckAndFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx])
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Headers[key] = base
				return results
			}
			t.Headers[key] = fmt.Sprintf("%s%s", base, boolCheckAndFalse[idx])
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Headers[key] = base
				return results
			}
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx])
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Cookies[key] = base
				return results
			}
			t.Cookies[key] = fmt.Sprintf("%s%s", base, boolCheckAndFalse[idx])
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Cookies[key] = base
				return results
			}
			t.Cookies[key] = base
		case target.VBODY:
			if t.BodyType == target.JSON {
				util.LogErr("JSON Body cannot be processed here!")
				return results
			}
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, boolCheckAndFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Body[key] = base
				return results
			}
		case target.VPATH:
			key = base
			t.Path[pos] = url.PathEscape(fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Path[pos] = base
				return results
			}
			t.Path[pos] = url.PathEscape(fmt.Sprintf("%s%s", base, boolCheckAndFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Path[pos] = base
				return results
			}
		}
		//content := html.UnescapeString(sbody)
		if scode != fcode || sbody != fbody && !strings.Contains(sbody, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.BOOLBLIND,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", base, boolCheckAndTrue[idx]),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", base, payloads.BuildTemplate(boolCheckAndTrue[idx], target.BOOLBLIND)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[pos] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[pos] = base
		}
	}

	return results
}

func BooleanOrCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	boolCheckOrTrue := payloads.BuildBoolPayloadSet(detection, false, true)
	boolCheckOrFalse := payloads.BuildBoolPayloadSet(detection, false, false)

	var scode int
	var sbody string
	var fcode int
	var fbody string
	var err error
	var pos int
	if l == target.VPATH {
		pos, _ = strconv.Atoi(key)
	}

	randstr := payloads.RandomStr()
	for idx := range len(boolCheckOrTrue) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", boolCheckOrTrue[idx]))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx])
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Headers[key] = base
				return results
			}
			t.Headers[key] = fmt.Sprintf("%s%s", randstr, boolCheckOrFalse[idx])
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Headers[key] = base
				return results
			}
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx])
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Cookies[key] = base
				return results
			}
			t.Cookies[key] = fmt.Sprintf("%s%s", randstr, boolCheckOrFalse[idx])
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Cookies[key] = base
				return results
			}
			t.Cookies[key] = base
		case target.VBODY:
			if t.BodyType == target.JSON {
				util.LogErr("JSON Body cannot be processed here!")
				return results
			}
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Params[key] = base
				return results
			}
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Body[key] = base
				return results
			}
		case target.VPATH:
			key = base
			t.Path[pos] = url.PathEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx]))
			scode, sbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Path[pos] = base
				return results
			}
			t.Path[pos] = url.PathEscape(fmt.Sprintf("%s%s", randstr, boolCheckOrFalse[idx]))
			fcode, fbody, err = GetComparisonData(t, client)
			if err != nil {
				util.LogErr(err.Error())
				t.Path[pos] = base
				return results
			}
		}
		//content := html.UnescapeString(sbody)
		if scode != fcode || sbody != fbody && !strings.Contains(sbody, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.BOOLBLIND,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", randstr, boolCheckOrTrue[idx]),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", randstr, payloads.BuildTemplate(boolCheckOrTrue[idx], target.BOOLBLIND)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[pos] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[pos] = base
		}
	}

	return results
}

func UnionCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	var idx int
	if l == target.VPATH {
		idx, _ = strconv.Atoi(key)
	}
	switch l {
	case target.VQUERY:
		t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]))
	case target.VHEADER:
		t.Headers[key] = fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection])
	case target.VCOOKIE:
		t.Cookies[key] = fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection])
	case target.VBODY:
		t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]))
	case target.VPATH:
		t.Path[idx] = url.PathEscape(fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]))
		key = base
	}
	bcode, bbody, err := GetComparisonData(t, client)
	if err != nil {
		util.LogErr(err.Error())
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
		return results
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.UnionCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VBODY:
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VPATH:
			t.Path[idx] = url.PathEscape(fmt.Sprintf("%s%s", base, payload))
			key = base
		}
		code, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		if ((strings.Contains(body, "N1QLSCAN") || strings.Contains(body, "nickel28")) || (code == bcode && body != bbody)) && !strings.Contains(body, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.UNION,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", base, payload),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", base, payloads.BuildTemplate(payload, target.UNION)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
	}

	return results
}

func StackedQueryCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	var idx int
	if l == target.VPATH {
		idx, _ = strconv.Atoi(key)
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.StackedQueryCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VBODY:
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VPATH:
			t.Path[idx] = url.PathEscape(fmt.Sprintf("%s%s", base, payload))
			key = base
		}
		_, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		if strings.Contains(body, "N1QLSCAN") {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.STACK,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", base, payload),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", base, payloads.BuildTemplate(payload, target.STACK)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
	}

	return results
}

func StringConcatCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	var idx int
	if l == target.VPATH {
		idx, _ = strconv.Atoi(key)
	}
	bcode, bbody, err := GetComparisonData(t, client)
	if err != nil {
		util.LogErr(err.Error())
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
		return results
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.StringConcatCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VBODY:
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VPATH:
			t.Path[idx] = url.PathEscape(fmt.Sprintf("%s%s", base, payload))
			key = base
		}
		code, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		if code == bcode && fuzzy.Match(bbody, body) {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.STRCONCAT,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", base, payload),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", base, payloads.BuildTemplate(payload, target.STRCONCAT)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
	}

	return results
}

func ErrorCheck(t target.Target, client *http.Client, detection int, base string, key string, l target.VulnLocation) []target.Vulnerable {
	var results []target.Vulnerable

	var idx int
	if l == target.VPATH {
		idx, _ = strconv.Atoi(key)
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.ErrorCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VHEADER:
			t.Headers[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VCOOKIE:
			t.Cookies[key] = fmt.Sprintf("%s%s", base, payload)
		case target.VBODY:
			t.Body[key] = url.QueryEscape(fmt.Sprintf("%s%s", base, payload))
		case target.VPATH:
			t.Path[idx] = url.PathEscape(fmt.Sprintf("%s%s", base, payload))
			key = base
		}
		_, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		if strings.Contains(body, "N1QLSCAN") && strings.Contains(body, "Abort: ") {
			results = append(results, target.Vulnerable{
				Location:        l,
				ExploitType:     target.ERROR,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   fmt.Sprintf("%s%s", base, payloads.EntryPoints[detection]),
				ExamplePayload:  fmt.Sprintf("%s%s", base, payload),
				Detection:       detection,
				PayloadTemplate: fmt.Sprintf("%s%s", base, payloads.BuildTemplate(payload, target.ERROR)),
			})
			switch l {
			case target.VQUERY:
				t.Params[key] = base
			case target.VHEADER:
				t.Headers[key] = base
			case target.VCOOKIE:
				t.Cookies[key] = base
			case target.VBODY:
				t.Body[key] = base
			case target.VPATH:
				t.Path[idx] = base
			}
			return results
		}
		switch l {
		case target.VQUERY:
			t.Params[key] = base
		case target.VHEADER:
			t.Headers[key] = base
		case target.VCOOKIE:
			t.Cookies[key] = base
		case target.VBODY:
			t.Body[key] = base
		case target.VPATH:
			t.Path[idx] = base
		}
	}

	return results
}

func JsonBooleanAndCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	boolCheckAndTrue := payloads.BuildBoolPayloadSet(detection, true, true)
	boolCheckAndFalse := payloads.BuildBoolPayloadSet(detection, true, false)
	var result map[string]any

	for idx := range len(boolCheckAndTrue) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", boolCheckAndTrue[idx]))
		}

		testTrue := strings.Replace(base, "[payloadpoint]", boolCheckAndTrue[idx], 1)
		json.Unmarshal([]byte(testTrue), &result)
		t.Body = result

		scode, sbody, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		testFalse := strings.Replace(base, "[payloadpoint]", boolCheckAndFalse[idx], 1)
		json.Unmarshal([]byte(testFalse), &result)
		t.Body = result
		fcode, fbody, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		//content := html.UnescapeString(sbody)
		if scode != fcode || sbody != fbody && !strings.Contains(sbody, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.BOOLBLIND,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", boolCheckAndTrue[idx], 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(boolCheckAndTrue[idx], target.BOOLBLIND), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}

	return results
}

func JsonBooleanOrCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	boolCheckOrTrue := payloads.BuildBoolPayloadSet(detection, false, true)
	boolCheckOrFalse := payloads.BuildBoolPayloadSet(detection, false, false)
	var result map[string]any

	for idx := range len(boolCheckOrTrue) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", boolCheckOrTrue[idx]))
		}
		testTrue := strings.Replace(base, "[payloadpoint]", boolCheckOrTrue[idx], 1)
		json.Unmarshal([]byte(testTrue), &result)
		t.Body = result

		scode, sbody, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		testFalse := strings.Replace(base, "[payloadpoint]", boolCheckOrFalse[idx], 1)
		json.Unmarshal([]byte(testFalse), &result)
		t.Body = result
		fcode, fbody, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		// content := html.UnescapeString(sbody)
		if scode != fcode || sbody != fbody && !strings.Contains(sbody, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.BOOLBLIND,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", boolCheckOrTrue[idx], 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(boolCheckOrTrue[idx], target.BOOLBLIND), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}

	return results
}

func JsonUnionCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	var result map[string]any
	test := strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1)

	json.Unmarshal([]byte(test), &result)

	t.Body = result
	bcode, bbody, err := GetComparisonData(t, client)
	if err != nil {
		util.LogErr(err.Error())
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
		return results
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.UnionCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		test := strings.Replace(base, "[payloadpoint]", payload, 1)

		json.Unmarshal([]byte(test), &result)

		t.Body = result

		code, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		fmt.Printf("Has fatal: %s\n%v\n", body, strings.Contains(body, `"status":"fatal"`))
		if ((strings.Contains(body, "N1QLSCAN") || strings.Contains(body, "nickel28")) || (code == bcode && body != bbody)) && !strings.Contains(body, `"status":"fatal"`) {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.UNION,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", payload, 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(payload, target.UNION), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}

	return results
}

func JsonStackedQueryCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	var result map[string]any
	for _, payload := range payloads.BuildPayloadSet(detection, payloads.StackedQueryCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		test := strings.Replace(base, "[payloadpoint]", payload, 1)

		json.Unmarshal([]byte(test), &result)

		t.Body = result

		_, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		if strings.Contains(body, "N1QLSCAN") {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.STACK,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", payload, 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(payload, target.STACK), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}

	return results
}

func JsonStringConcatCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	var result map[string]any
	test := strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1)

	json.Unmarshal([]byte(test), &result)

	t.Body = result
	bcode, bbody, err := GetComparisonData(t, client)
	if err != nil {
		util.LogErr(err.Error())
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
		return results
	}

	for _, payload := range payloads.BuildPayloadSet(detection, payloads.StringConcatCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		test := strings.Replace(base, "[payloadpoint]", payload, 1)

		json.Unmarshal([]byte(test), &result)

		t.Body = result

		code, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		if code == bcode && fuzzy.Match(bbody, body) {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.STRCONCAT,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", payload, 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(payload, target.STRCONCAT), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}
	return results
}

func JsonErrorCheck(t target.Target, client *http.Client, detection int, base string, key string) []target.Vulnerable {
	var results []target.Vulnerable

	var result map[string]any
	for _, payload := range payloads.BuildPayloadSet(detection, payloads.ErrorCheckTemplates) {
		if Verbose {
			util.LogVerbose(fmt.Sprintf("Testing payload: %s", payload))
		}
		test := strings.Replace(base, "[payloadpoint]", payload, 1)

		json.Unmarshal([]byte(test), &result)

		t.Body = result

		_, body, err := GetComparisonData(t, client)
		if err != nil {
			util.LogErr(err.Error())
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		if strings.Contains(body, "N1QLSCAN") && strings.Contains(body, "Abort: ") {
			results = append(results, target.Vulnerable{
				Location:        target.VBODY,
				ExploitType:     target.ERROR,
				Parameter:       key,
				BasePayload:     base,
				DetectPayload:   strings.Replace(base, "[payloadpoint]", payloads.EntryPoints[detection], 1),
				ExamplePayload:  strings.Replace(base, "[payloadpoint]", payload, 1),
				Detection:       detection,
				PayloadTemplate: strings.Replace(base, "[payloadpoint]", payloads.BuildTemplate(payload, target.ERROR), 1),
			})
			var result map[string]any
			json.Unmarshal([]byte(base), &result)
			t.Body = result
			return results
		}
		var result map[string]any
		json.Unmarshal([]byte(base), &result)
		t.Body = result
	}

	return results
}

func GetComparisonData(t target.Target, c *http.Client) (int, string, error) {
	resp, err := DoRequest(t, c)
	if err != nil {
		return 0, "", fmt.Errorf("Error: Unable to communicate with the target application. Please check the application is reachable and the provided URL / request is correct.")
	}
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, "", fmt.Errorf("Error: Unable to read the response body.")
	}
	respBody := string(respBodyBytes)
	return resp.StatusCode, respBody, nil

}

func Find(s string, data map[string]any) bool {
	r := 0
	for k, v := range data {
		if k == s {
			return true
		}
		if c, ok := v.(map[string]any); ok {
			if Find(s, c) {
				r += 1
			}
		}
	}
	if r > 0 {
		return true
	}
	return false
}

func LocateParameter(target target.Target, v string) []Mode {
	result := []Mode{}

	if _, exists := target.Params[v]; exists {
		result = append(result, Query)
	}

	if Find(v, target.Body) {
		result = append(result, Body)
	}

	if _, exists := target.Headers[v]; exists {
		result = append(result, Header)
	}

	if _, exists := target.Cookies[v]; exists {
		result = append(result, Cookie)
	}

	if slices.Contains(target.Path, v) {
		result = append(result, Path)
	}

	return result
}
