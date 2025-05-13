package config

import (
	"log"

	"github.com/spf13/viper"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/pathutil"
)

type JwtConfig struct {
	AccessTokenPrivateKey  string `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY"`
	AccessTokenPublicKey   string `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY"`
	AccessTokenExpiresIn   string `mapstructure:"ACCESS_TOKEN_EXPIRES_IN"`
	AccessTokenMaxAge      string `mapstructure:"ACCESS_TOKEN_MAX_AGE"`
	RefreshTokenPrivateKey string `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY"`
	RefreshTokenPublicKey  string `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY"`
	RefreshTokenExpiresIn  string `mapstructure:"REFRESH_TOKEN_EXPIRES_IN"`
	RefreshTokenMaxAge     string `mapstructure:"REFRESH_TOKEN_MAX_AGE"`
}

type DatabaseConfig struct {
	DBHost     string `mapstructure:"POSTGRES_HOST"`
	DBPort     string `mapstructure:"POSTGRES_PORT"`
	DBName     string `mapstructure:"POSTGRES_DB"`
	DBUser     string `mapstructure:"POSTGRES_USER"`
	DBPassword string `mapstructure:"POSTGRES_PASSWORD"`
}

type ServerConfig struct {
	AuthServerHttpUrl string `mapstructure:"AUTH_SERVICE_HTTP_URL"`
	AuthServerGrpcUrl string `mapstructure:"AUTH_SERVICE_GRPC_URL"`
}

type Config struct {
	Environment  string `mapstructure:"ENVIRONMENT"`
	ServerConfig ServerConfig
	Database     DatabaseConfig
	Jwt          JwtConfig
}

func LoadConfig() (config *Config, err error) {
	rootDir, err := pathutil.FindProjectRoot()
	if err != nil || rootDir == "" {
		log.Fatal(err)
	}

	viper.AddConfigPath(rootDir)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Unable to read in config: %v", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode into struct: %v", err)
	}

	return
}
