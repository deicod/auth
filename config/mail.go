package config

type Mail struct {
	Host   string
	Port   int
	User   string
	Pass   string
	From   string
	UseSSL bool
	// VerificationURL and PasswordResetURL are optional application page URLs.
	// The mailer appends the token as a URL-encoded query parameter.
	VerificationURL  string
	PasswordResetURL string
}

func DefaultMail() Mail {
	return Mail{
		Host:   "mailserverx.de",
		Port:   465,
		User:   "dev@icod.de",
		Pass:   "",
		From:   "dev@icod.de",
		UseSSL: true,
	}
}
