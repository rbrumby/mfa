# mfa

## A virtual (terminal-based) Multi-factor-Authentication device.
### Can be used in the same way as tools like Google Authenticator.

Tools like Google Authenticator are usually run on a separate device to the device you use to log in so that if one device is lost / stolen, all credentials (SSH keys, saved passwords in browsers, etc) are not compromised.

This utility is really intended for situations like logging into your AWS account where you will enter the password (you don't keep it saved in your browser!) and have MFA configured but don't want to use a phone or are concerned about loss or damage to your phone.

The magic is all done by [pquerna/otp](http://github.com/pquerna/otp).
This utility wraps the above library into an executable and add flags for setting algorithms, colors, timing options, etc.

To use this with AWS, if you already have an MFA device associated with your account, you will need to replace it.
Remove the existing device under your accounts "My Security Credentials", add a new Virtual MFA device, choose the option to "Show secret key" & save the key to $HOME/.mfa/secret. You should also make sure this file is only readable to your user (you will get a warning when running mfa if you do not)!

"go run mfa.go --help" for mpre details on the options