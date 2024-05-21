package utils

import "golang.org/x/crypto/bcrypt"

func GenerateHash(password string) (string, error) {
	const cost = 14
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
func ComparePasswords(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err
}
