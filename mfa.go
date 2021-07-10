package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type Color string

const (
	SecretFileNameEnv       = "MFA_SECRET_FILE"
	Red               Color = "\033[31m"
	Green             Color = "\033[32m"
	Yellow            Color = "\033[33m"
	Blue              Color = "\033[34m"
	Purple            Color = "\033[35m"
	Cyan              Color = "\033[36m"
	Gray              Color = "\033[37m"
	White             Color = "\033[97m"
)

//otp library doesn't provide a map to translate algorithm names
var algMap map[string]otp.Algorithm = map[string]otp.Algorithm{
	"SHA1":   otp.AlgorithmSHA1,
	"SHA256": otp.AlgorithmSHA256,
	"SHA512": otp.AlgorithmSHA512,
	"MD5":    otp.AlgorithmMD5,
}

var TerminalColors map[string]Color = map[string]Color{
	"red":    Red,
	"green":  Green,
	"yellow": Yellow,
	"blue":   Blue,
	"purple": Purple,
	"cyan":   Cyan,
	"gray":   Gray,
	"white":  White,
}

//Writer is an interface which an MFADevce will write to
type Writer interface {
	Write(p []byte) error
	Warn(p []byte) error
	Error(p []byte) error
}

//Terminsl is a Writer for writing out OTP codes & error/warning messages
type Terminal struct {
	Pattern      string
	Prefix       string
	DefaultColor Color
	WarningColor Color
	ErrorColor   Color
}

//NewTerminal creates a new Terminal using functional options to set the output colors
func NewTerminal(options ...func(*Terminal)) *Terminal {
	term := &Terminal{
		Pattern:      "\r%s%s [%s] %s",
		Prefix:       "default",
		DefaultColor: Green,
		WarningColor: Cyan,
		ErrorColor:   Red,
	}
	for _, o := range options {
		o(term)
	}
	return term
}

//Prefix is a functional option for setting a prefix to help identify an OTP (if you have multiple running)
func Prefix(pre string) func(*Terminal) {
	return func(t *Terminal) {
		if pre != "" {
			t.Prefix = pre
		}
	}
}

//DefaultColor is a functional option for setting the terminal default text color
func DefaultColor(c Color) func(*Terminal) {
	return func(t *Terminal) {
		if c != "" {
			t.DefaultColor = c
		}
	}
}

//WarningColor is a functional option for setting the terminal warning text color
func WarningColor(c Color) func(*Terminal) {
	return func(t *Terminal) {
		if c != "" {
			t.WarningColor = c
		}
	}
}

//ErrorColor is a functional option for setting the terminal error text color
func ErrorColor(c Color) func(*Terminal) {
	return func(t *Terminal) {
		if c != "" {
			t.ErrorColor = c
		}
	}
}

//Write writes in the DefaultColor of the Terminal
func (t *Terminal) Write(p []byte) error {
	fmt.Fprintf(os.Stdout, t.Pattern, t.DefaultColor, t.Prefix, time.Now().Format(time.RFC3339), p)
	return nil
}

//Warn writes in the WarningColor of the Terminal
func (t *Terminal) Warn(p []byte) error {
	fmt.Fprintf(os.Stdout, t.Pattern, t.WarningColor, t.Prefix, time.Now().Format(time.RFC3339), p)
	return nil
}

//Error writes in the ErrorColor of the Terminal
func (t *Terminal) Error(p []byte) error {
	fmt.Fprintf(os.Stderr, t.Pattern, t.ErrorColor, t.Prefix, time.Now().Format(time.RFC3339), p)
	return nil
}

type MFADevice struct {
	Secret          []byte
	Writer          Writer
	UpdateFrequency time.Duration
	TOTPOptions     totp.ValidateOpts
}

//NewMFADevice creates a new MFADevice using functional options
func NewMFADevice(options ...func(*MFADevice)) *MFADevice {
	//By default use a Terminal
	term := NewTerminal()

	device := &MFADevice{
		TOTPOptions:     totp.ValidateOpts{},
		Writer:          term,
		UpdateFrequency: time.Second,
	}
	for _, o := range options {
		o(device)
	}
	return device
}

//Run runs the MFADevice
func (d *MFADevice) Run() {
	ticker := time.NewTicker(d.UpdateFrequency)
	for {
		t := <-ticker.C
		out, err := totp.GenerateCodeCustom(string(d.Secret), t, d.TOTPOptions)
		if err != nil {
			panic(err)
		}
		if t.Second() >= 55 || (t.Second() < 30 && t.Second() >= 25) {
			err = d.Writer.Warn([]byte(out))
			if err != nil {
				panic(err)
			}
		} else {
			err = d.Writer.Write([]byte(out))
			if err != nil {
				panic(err)
			}
		}
	}
}

//Secret is a functional option to set a secret on an MFADevice
func Secret(secret string) func(*MFADevice) {
	return func(d *MFADevice) {
		if secret != "" {
			d.Secret = []byte(secret)
		}
	}
}

//SecretFromFile is a functional option to tell an MFADevice to read the secret from a file
func SecretFromFile(file *os.File) func(*MFADevice) {
	return func(d *MFADevice) {
		if file != nil {
			stat, err := file.Stat()
			if err != nil {
				panic(err)
			}
			if stat.Mode().Perm() > 0o700 {
				d.Writer.Warn([]byte(fmt.Sprintf("WARNING - secret file %q is not secure\n", file.Name())))
			}

			secret, err := ioutil.ReadAll(file)
			if err != nil {
				panic(err)
			}
			d.Secret = secret
		}
	}
}

//Output is a functional option to tell an MFADevice which Writer to output OTP codes to
func Output(w Writer) func(*MFADevice) {
	return func(d *MFADevice) {
		if w != nil {
			d.Writer = w
		}
	}
}

//UpdateFrequency is a functional option to tell an MFADevice to read the secret from a file
func UpdateFrequency(p time.Duration) func(*MFADevice) {
	return func(d *MFADevice) {
		if p != 0 {
			d.UpdateFrequency = p
		}
	}
}

func RefreshPeriod(per uint) func(*MFADevice) {
	return func(d *MFADevice) {
		if per != 0 {
			d.TOTPOptions.Period = per
		}
	}
}

func Digits(dig otp.Digits) func(*MFADevice) {
	return func(d *MFADevice) {
		d.TOTPOptions.Digits = dig
	}
}

func Algorithm(alg string) func(*MFADevice) {
	return func(d *MFADevice) {
		if alg != "" {
			d.TOTPOptions.Algorithm = algMap[alg]
		}
	}
}

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

	term := NewTerminal(
		Prefix(*prefix),
		DefaultColor(TerminalColors[*defaultColor]),
		WarningColor(TerminalColors[*warningColor]),
		ErrorColor(TerminalColors[*errorColor]),
	)

	device := NewMFADevice(
		Output(term),
		Algorithm(*algorithm),
		RefreshPeriod(*period),
		Digits(otp.Digits(*digits)),
		UpdateFrequency(time.Second*time.Duration(*frequency)),
	)

	switch {
	case *secret != "":
		//Use the secret if one is passed
		Secret(*secret)(device)
	case *secretFileName != "":
		//Otherwise use secret-file if one is passed
		secFile, err := os.Open(*secretFileName)
		if err != nil {
			panic(err)
		}
		SecretFromFile(secFile)(device)
	case os.Getenv(SecretFileNameEnv) != "":
		//Otherwise use MFA_SECRET_FILE environment variable if it is set
		env := os.Getenv(SecretFileNameEnv)
		secFile, err := os.Open(env)
		if err != nil {
			panic(err)
		}
		SecretFromFile(secFile)(device)
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
		SecretFromFile(secFile)(device)
	}

	device.Run()
}
