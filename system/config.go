package system

type MetaConfig struct {
	SiteName        string                 `json:"sitename"`
	SiteURL         string                 `json:"siteurl"`
	DevelopmentMode bool                   `json:"devmode"`
	CopyrightName   string                 `json:"copyright-name"`
	TemplateData    map[string]interface{} `json:"templatedata"`
}
type Config struct {
	Meta           MetaConfig        `json:"Meta,omitempty"`
	Keys           KeyConfig         `json:"Keys,omitempty"`
	Sec            SecurityConfig    `json:"Security,omitempty"`
	ReverseProxy   map[string]string `json:"ReverseProxy"`
	ConfigFilePath string            `json:"-"` // path to config for reload, empty if stdin
}

type KeyConfig struct {
	GoogleClientID    string `json:"GoogleClientID"`
	GoogleSecretKey   string `json:"GoogleSecretKey"`
	GithubClientID    string `json:"GithubClientID"`
	GithubSecretKey   string `json:"GithubSecretKey"`
	TwitterClientID   string `json:"TwitterClientID"`
	TwitterSecretKey  string `json:"TwitterSecretKey"`
	LinkedInClientID  string `json:"LinkedInClientID"`
	LinkedInSecretKey string `json:"LinkedInSecretKey"`
	PayPalClientID    string `json:"PayPalClientID"`
	PayPalSecretKey   string `json:"PayPalSecretKey"`
	SendgridUser      string `json:"SendgridUser"`
	SendgridPassword  string `json:"SendgridPassword"`
	MailgunUser       string `json:"MailgunUser"`
	MailgunPassword   string `json:"MailgunPassword"`
	TwilioSID         string `json:"TwilioSID"`
	TwilioAuthToken   string `json:"TwilioAuthToken"`
}

type SecurityConfig struct {
	HashKey     string `json:"hash-key"`
	BlockKey    string `json:"block-key"`
	CSRFKey     string `json:"csrf-key"`
	CookieName  string `json:"cookie-name"`
	Whitelist   string `json:"whitelist"`
	Blacklist   string `json:"blacklist"`
	ServePublic bool   `json:"servepublic"` // Serve All Unhandled URL in ./public
	BoltDB      string `json:"database"`
}
