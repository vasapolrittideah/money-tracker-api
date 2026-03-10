package config

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration structure that aggregates all sub-configs
// loaded from environment variables or a .env file.
type Config struct {
	App      AppConfig      `mapstructure:",squash"`
	Database DatabaseConfig `mapstructure:",squash"`
	JWT      JWTConfig      `mapstructure:",squash"`
	SMTP     SMTPConfig     `mapstructure:",squash"`
}

// AppConfig holds general application settings.
type AppConfig struct {
	Port string `mapstructure:"APP_PORT"`
	Env  string `mapstructure:"APP_ENV"`
}

// DatabaseConfig holds the connection details for the primary database.
type DatabaseConfig struct {
	Host     string `mapstructure:"DB_HOST"`
	Port     string `mapstructure:"DB_PORT"`
	User     string `mapstructure:"DB_USER"`
	Password string `mapstructure:"DB_PASSWORD"`
	Name     string `mapstructure:"DB_NAME"`
}

// JWTConfig holds the secret keys and expiry durations for access and refresh tokens.
type JWTConfig struct {
	AccessSecretKey  string        `mapstructure:"JWT_ACCESS_SECRET"`
	RefreshSecretKey string        `mapstructure:"JWT_REFRESH_SECRET"`
	AccessExpiresIn  time.Duration `mapstructure:"JWT_ACCESS_EXPIRES_IN"`
	RefreshExpiresIn time.Duration `mapstructure:"JWT_REFRESH_EXPIRES_IN"`
	Issuer           string        `mapstructure:"JWT_ISSUER"`
}

// SMTPConfig holds the connection details for the SMTP server used to send emails.
type SMTPConfig struct {
	Host     string `env:"SMTP_HOST"`
	Port     int    `env:"SMTP_PORT"`
	Username string `env:"SMTP_USERNAME"`
	Password string `env:"SMTP_PASSWORD"`
	From     string `env:"SMTP_FROM"`
}

// RedisConfig holds the connection details for Redis.
type RedisConfig struct {
	Addr     string `mapstructure:"REDIS_ADDR"`
	Password string `mapstructure:"REDIS_PASSWORD"`
}

// Load reads configuration from a .env file and environment variables,
// applies defaults for optional fields, unmarshals the result into a Config
// struct, and validates that all required fields are present.
func Load() (*Config, error) {
	viper.SetConfigFile(".env")

	viper.AutomaticEnv()

	viper.SetDefault("APP_PORT", "5050")
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("JWT_ACCESS_EXPIRES_IN", "15m")
	viper.SetDefault("JWT_REFRESH_EXPIRES_IN", "7d")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate checks that all required configuration fields are set
// and returns a descriptive error for the first missing field found.
func (c *Config) validate() error {
	if c.Database.Host == "" {
		return errors.New("DB_HOST is required")
	}
	if c.Database.Port == "" {
		return errors.New("DB_PORT is required")
	}
	if c.Database.Name == "" {
		return errors.New("DB_NAME is required")
	}
	if c.JWT.AccessSecretKey == "" {
		return errors.New("JWT_ACCESS_SECRET is required")
	}
	if c.JWT.RefreshSecretKey == "" {
		return errors.New("JWT_REFRESH_SECRET is required")
	}
	return nil
}

// IsProduction reports whether the application is running in production mode.
func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}

// IsDevelopment reports whether the application is running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}
