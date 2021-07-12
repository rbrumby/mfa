package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rbrumby/mfa"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"%s prints a One-Time-Passcode (OTP), refreshing it every n seconds as defined by -refresh-seconds.\n"+
				"If -secret is provided, it will takes precedence (NOTE this is the least secure option).\n"+
				"Else, if -secret-file is provided, the secret will be read from that file.\n"+
				"Else, if environment variable MFA_SECRET_FILE is provided,the secret will be read from that file.\n"+
				"Else, an attempt will be made to read the secret from $HOME/.mfa/secret.\n",
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	secret := flag.String("secret", "", "the OTP secret")
	secretFileName := flag.String("secret-file", "", "filename containing the OTP secret")
	frequency := flag.Uint("update-frequency", 1, "the number of seconds between OTP recalculations. Defaults to 1")
	period := flag.Uint("refresh-period", 30, "the number of seconds an OTP is valid for. Defaults to 30")
	prefix := flag.String("prefix", "mfa", "a prefix to print before the OTP")
	digits := flag.Int("digits", 6, "the number of digits in the OTP. Defaults to 6")
	algorithm := flag.String("algorithm", "SHA1", "the algorithm to use to calculate the OTP")
	defaultColor := flag.String("color", "", "Terminal text color for default output. Valid colors are red, green, yellow, blue, purple, cyan, gray & white")
	warningColor := flag.String("warn-color", "", "Terminal text color for warning output (when the OTP is close to expiry)")
	errorColor := flag.String("error-color", "", "Terminal text color for outputting errors")
	flag.Parse()

	term := mfa.NewTerminal(
		mfa.Prefix(*prefix),
		mfa.DefaultColor(mfa.TerminalColors[*defaultColor]),
		mfa.WarningColor(mfa.TerminalColors[*warningColor]),
		mfa.ErrorColor(mfa.TerminalColors[*errorColor]),
	)

	device := mfa.NewMFADevice(
		mfa.Output(term),
		mfa.Algorithm(*algorithm),
		mfa.RefreshPeriod(*period),
		mfa.Digits(*digits),
		mfa.UpdateFrequency(time.Second*time.Duration(*frequency)),
	)

	switch {
	case *secret != "":
		//Use the secret if one is passed
		mfa.Secret(*secret)(device)
	case *secretFileName != "":
		//Otherwise use secret-file if one is passed
		secFile, err := os.Open(*secretFileName)
		if err != nil {
			panic(err)
		}
		mfa.SecretFromFile(secFile)(device)
	case os.Getenv(mfa.SecretFileNameEnv) != "":
		//Otherwise use MFA_SECRET_FILE environment variable if it is set
		env := os.Getenv(mfa.SecretFileNameEnv)
		secFile, err := os.Open(env)
		if err != nil {
			panic(err)
		}
		mfa.SecretFromFile(secFile)(device)
	default:
		//Otherwise default to $HOME/.totp/secret
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		secretFName := homeDir + "/.mfa/secret"
		secFile, err := os.Open(secretFName)
		if err != nil {
			panic(err)
		}
		mfa.SecretFromFile(secFile)(device)
	}

	device.Run()
}
