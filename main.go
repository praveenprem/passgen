package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"regexp"
	"strings"
)

/**

******************************************
*                                        *
*      ********         ********         *
*      **      **       **      **       *
*      **       **      **       **      *
*      **      **       **      **       *
*      ********         ********         *
*      **               **               *
*      **               **               *
*                                        *
******************************************
         ** Praveen Premaratne **

 * Package name: main
 * Project name: Password Generator
 * Created by: Praveen Premaratne
 * Created on: 2019-01-05 18:43
 */

type UserData struct {
	Username, Password, ConfirmPassword string
}

const (
	DefaultCost         int    = 15
	PromptUsername      string = "New username: "
	PromptPasswd        string = "Password: "
	PromptConfirmPasswd string = "Confirm password: "
	PasswdMismatch      string = "Passwords didn't match"
	InsufficientPasswd string = "Password require minimum of:\n" +
		" 6 or more characters\n" +
		" 1 or more UPPERCASE\n" +
		" 1 or more lowercase\n" +
		" 1 or more digit\n"
)

var userData = UserData{}

func GetUserData() UserData {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print(PromptUsername)
	username, _ := reader.ReadString('\n')
	fmt.Print(PromptPasswd)
	password, _ := reader.ReadString('\n')
	fmt.Print(PromptConfirmPasswd)
	confirmPassword, _ := reader.ReadString('\n')

	return UserData{Username: strings.TrimSuffix(username, "\n"),
		Password:        strings.TrimSuffix(password, "\n"),
		ConfirmPassword: strings.TrimSuffix(confirmPassword, "\n")}
}

func PasswordValidate(user UserData) {
	var passwordStrength [3]string
	passwordStrength[0] = "([a-z]+)"
	passwordStrength[1] = "([A-Z]+)"
	passwordStrength[2] = "([0-9]+)"

	for _, v := range passwordStrength{
		r, err := regexp.Compile(v)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if r.MatchString(user.Password) == false {
			fmt.Printf(InsufficientPasswd)
			os.Exit(1)
		}
	}

	if len(user.Password) < 6 {
		fmt.Printf(InsufficientPasswd)
		os.Exit(1)
	}

	if user.Password != user.ConfirmPassword {
		fmt.Println(PasswdMismatch)
		os.Exit(1)
	}

}

func GeneratePasswordHash(password string, cost int) (string, error) {
	byteHash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(byteHash), err
}

func main() {
	userData = GetUserData()

	PasswordValidate(userData)

	fmt.Printf("%s: %s \n", "Generating new password for user", userData.Username)
	generatedPassword, err := GeneratePasswordHash(strings.TrimSuffix(userData.Password, "\n"), DefaultCost)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		fmt.Printf("%s:%s\n", userData.Username, generatedPassword)
	}
}
