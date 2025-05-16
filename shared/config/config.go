package config

import (
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/path_util"
)

type SecurityConfig struct {
	AccessTokenPrivateKey  string        `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY"`
	AccessTokenPublicKey   string        `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY"`
	AccessTokenExpiresIn   time.Duration `mapstructure:"ACCESS_TOKEN_EXPIRES_IN"`
	AccessTokenMaxAge      string        `mapstructure:"ACCESS_TOKEN_MAX_AGE"`
	RefreshTokenPrivateKey string        `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY"`
	RefreshTokenPublicKey  string        `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY"`
	RefreshTokenExpiresIn  time.Duration `mapstructure:"REFRESH_TOKEN_EXPIRES_IN"`
	RefreshTokenMaxAge     string        `mapstructure:"REFRESH_TOKEN_MAX_AGE"`
}

type DatabaseConfig struct {
	DBHost     string `mapstructure:"POSTGRES_HOST"`
	DBPort     string `mapstructure:"POSTGRES_PORT"`
	DBName     string `mapstructure:"POSTGRES_DB"`
	DBUser     string `mapstructure:"POSTGRES_USER"`
	DBPassword string `mapstructure:"POSTGRES_PASSWORD"`
}

type ServerConfig struct {
	AuthServerHttpPort string `mapstructure:"AUTH_SERVICE_HTTP_PORT"`
	AuthServerGrpcPort string `mapstructure:"AUTH_SERVICE_GRPC_PORT"`
	UserServerHttpPort string `mapstructure:"USER_SERVICE_HTTP_PORT"`
	UserServerGrpcPort string `mapstructure:"USER_SERVICE_GRPC_PORT"`
}

type Config struct {
	Environment string         `mapstructure:"ENVIRONMENT"`
	Server      ServerConfig   `mapstructure:",squash"`
	Security    SecurityConfig `mapstructure:",squash"`
	Database    DatabaseConfig `mapstructure:",squash"`
}

func LoadConfig() (config *Config, err error) {
	rootDir, err := path_util.FindProjectRoot()
	if err != nil || rootDir == "" {
		log.Fatal(err)
	}

	viper.SetConfigType("env")
	viper.SetConfigName(".env")
	viper.AddConfigPath(rootDir)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Unable to read in config: %v", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode into struct: %v", err)
	}

	return
}
