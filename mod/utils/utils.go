package utils

import "fmt"

// ExtractHeader retains its legacy signature but always handles casing safely.
// Multiple fields/values are ambiguous, including differently cased duplicates.
func ExtractHeader(headers map[string][]string, key string, _ bool) (string, error) {
	value, found, err := singleHeader(headers, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("header %s not found", key)
	}
	return value, nil
}
