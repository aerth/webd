package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type MetaConfig struct {
	Version         string                 `json:"-"`
	ListenAddr      string                 `json:"listen"`
	ListenAddrTLS   string                 `json:"listentls"`
	SiteName        string                 `json:"sitename"`
	SiteURL         string                 `json:"siteurl"`
	DevelopmentMode bool                   `json:"devmode"`
	CopyrightName   string                 `json:"copyright-name"`
	TemplateData    map[string]interface{} `json:"templatedata"`
	LiveTemplate    bool                   `json:"livetemplate"`
	PathTemplates   string                 `json:"templatedir"`
	PathPublic      string                 `json:"publicdir"`
}
type Config struct {
	Meta           MetaConfig        `json:"Meta,omitempty"`
	Keys           KeyConfig         `json:"Keys,omitempty"`
	Sec            SecurityConfig    `json:"Security,omitempty"`
	ReverseProxy   map[string]string `json:"ReverseProxy"`
	Webhook        map[string]string `json:"Webhook"`
	ConfigFilePath string            `json:"-"` // empty if stdin ($PWD used)
	DoMongo        bool              `json:"use-mongo"`
	Telegram       struct {
		AdminUsername string `json:"adminUser"`
		AdminChatID   int64  `json:"adminChat"`
		AuditChatID   int64  `json:"auditChat"`
	} `json:"Telegram"`
	Diamond struct {
		Kicks      bool `json:"Kicks"`
		SocketPath string
	} `json:"Diamond"`
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
	TelegramBot       string `json:"TelegramBot"`
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
	EnableShell bool   `json:"EnableShell"`
}

func CheckConfig(config *Config) error {
	// minimal config needed
	if config.Meta.Version == "" {
		config.Meta.Version = "webd"
	}
	if config.Meta.PathPublic == "" {
		config.Meta.PathPublic = "./www/public"
	}
	if config.Meta.PathTemplates == "" {
		config.Meta.PathTemplates = "./www/templates"
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if config.ConfigFilePath != "" {
		dir, err = filepath.Abs(filepath.Dir(config.ConfigFilePath))
		if err != nil {
			return fmt.Errorf("error %v", err)
		}
		log.Println("ConfigFilePath Directory:", dir)
	} else {
		log.Println("Using current working directory:", dir)
	}

	if !filepath.IsAbs(config.Meta.PathPublic) {
		log.Printf("public path %q isnt abs, making abs", config.Meta.PathPublic)
		config.Meta.PathPublic, err = filepath.Abs(filepath.Join(dir, config.Meta.PathPublic))
		if err != nil {
			return err
		}
	}
	if !filepath.IsAbs(config.Meta.PathTemplates) {
		log.Printf("templates path %q isnt abs, making abs", config.Meta.PathTemplates)
		config.Meta.PathTemplates, err = filepath.Abs(filepath.Join(dir, config.Meta.PathTemplates))
		if err != nil {
			return err
		}
	}
	for _, dirname := range []string{config.Meta.PathPublic, config.Meta.PathTemplates} {
		println("checking directory:", dirname)
		if s, err := os.Stat(dirname); err != nil || !s.IsDir() {
			if err != nil {
				println("fatal")
				return err
			}
			return fmt.Errorf("is not a dir: %v", dirname)
		}
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
	_, err = os.Open(config.Meta.PathPublic)
	if err != nil {
		return fmt.Errorf("Warning: no public web assets found. Did you forget to unzip webassets.zip to ./www/public? Try: make www/public (not found: %q (%v))", config.Meta.PathPublic, err)
	}

	return nil
}
