package util

import "regexp"

func CheckFormat(exfilHost string) bool {
	r := regexp.MustCompile("^http(s|)://.+?(:[0-9]{1,5}|)/.*$")
	return r.MatchString(exfilHost)
}
