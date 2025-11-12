package config

type Mail struct {
	Host   string
	Port   int
	User   string
	Pass   string
	From   string
	UseSSL bool
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
