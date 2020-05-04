package system

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type MetaConfig struct {
	ListenAddr      string                 `json:"listen"`
	ListenAddrTLS   string                 `json:"listentls"`
	SiteName        string                 `json:"sitename"`
	SiteURL         string                 `json:"siteurl"`
	DevelopmentMode bool                   `json:"devmode"`
	CopyrightName   string                 `json:"copyright-name"`
	TemplateData    map[string]interface{} `json:"templatedata"`
	Version         string                 `json:"-"`
}
type Config struct {
	Meta           MetaConfig        `json:"Meta,omitempty"`
	Keys           KeyConfig         `json:"Keys,omitempty"`
	Sec            SecurityConfig    `json:"Security,omitempty"`
	ReverseProxy   map[string]string `json:"ReverseProxy"`
	ConfigFilePath string            `json:"-"` // unused in config.json, path to config for reload, empty if stdin
	DoMongo        bool              `json:"use-mongo"`
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
	OpenSignups bool   `json:"open-signups"`
}

func checkConfig(config *Config) error {
	// minimal config needed
	if config.Meta.Version == "" {
		config.Meta.Version = "webd"
	}

	if config.Meta.SiteURL == "" {
		return fmt.Errorf("config needs Meta.siteurl")
	}
	if config.Sec.BlockKey == "" {
		return fmt.Errorf("config needs Security.block-key")
	}
	if config.Sec.CSRFKey == "" {
		return fmt.Errorf("config needs Security.csrf-key")
	}
	if config.Sec.HashKey == "" {
		return fmt.Errorf("config needs Security.hash-key")
	}
	if config.Sec.CookieName == "" {
		return fmt.Errorf("config needs Security.cookie-name")
	}

	// override is $PORT or $SITEURL are used (heroku, etc?)
	if port := os.Getenv("PORT"); port != "" {
		log.Println("overriding flags and config file with $PORT", port)
		config.Meta.ListenAddr = ":" + port
	}
	if siteurl := os.Getenv("SITEURL"); siteurl != "" {
		log.Println("overriding flags and config file with $SITEURL", siteurl)
		config.Meta.SiteURL = siteurl
	}

	// check www/public exists
	_, err := os.Open(filepath.Join("www", "public"))
	if err != nil {
		return fmt.Errorf("Warning: no public web assets found. Did you forget to unzip webassets.zip to ./www/public? Try: make www/public")
	}

	return nil
}
