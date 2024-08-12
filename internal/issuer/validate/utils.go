package validate

import (
	"slices"
	"strings"
)

// containsString checks if a string is present in a slice of strings.
func containsString(s string, slice []string) bool {
	index := slices.IndexFunc(slice, func(str string) bool {
		return str == s
	})

	return index != -1
}

// containsInt checks if a string is present in a slice of strings.
func containsInt(d int, slice []int) bool {
	for _, v := range slice {
		if v == d {
			return true
		}
	}
	return false
}

// hasSuffix checks if the given string s ends with the specified suffix.
func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}
