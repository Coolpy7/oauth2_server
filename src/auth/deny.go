package auth

import "bytes"

var KindWord = []byte("$")

func InjectionPass(word []byte) bool {
	if bytes.Contains(word, KindWord) {
		return false
	}
	return true
}
