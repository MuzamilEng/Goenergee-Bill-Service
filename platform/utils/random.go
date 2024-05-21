package utils

import (
	"math/rand"
	"time"
)

func GenerateRandomString(n int) string {
	// Define the alphabet
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Initialize a byte slice to store the generated characters
	result := make([]byte, n)

	// Generate random characters and append them to the result slice
	for i := range result {
		result[i] = alphabet[rand.Intn(len(alphabet))]
	}

	// Convert the byte slice to a string and return
	return string(result)
}
