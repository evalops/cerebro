package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/secretsource"
)

type credentialSourceSettings struct {
	Kind           string
	FileDir        string
	VaultAddress   string
	VaultToken     string
	VaultNamespace string
	VaultPath      string
	VaultKVVersion int
}

func loadCredentialSourceSettings() credentialSourceSettings {
	return credentialSourceSettings{
		Kind:           strings.ToLower(strings.TrimSpace(bootstrapConfigValue("CEREBRO_CREDENTIAL_SOURCE", secretsource.KindEnv))),
		FileDir:        bootstrapConfigValue("CEREBRO_CREDENTIAL_FILE_DIR", ""),
		VaultAddress:   bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_ADDRESS", ""),
		VaultToken:     bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_TOKEN", ""),
		VaultNamespace: bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_NAMESPACE", ""),
		VaultPath:      bootstrapConfigValue("CEREBRO_CREDENTIAL_VAULT_PATH", ""),
		VaultKVVersion: bootstrapConfigInt("CEREBRO_CREDENTIAL_VAULT_KV_VERSION", 2),
	}
}

func newCredentialConfigSource(settings credentialSourceSettings) (secretsource.Source, error) {
	if settings.Kind == "" {
		settings.Kind = secretsource.KindEnv
	}
	return secretsource.New(secretsource.Config{
		Kind:           settings.Kind,
		FileDir:        settings.FileDir,
		VaultAddress:   settings.VaultAddress,
		VaultToken:     settings.VaultToken,
		VaultNamespace: settings.VaultNamespace,
		VaultPath:      settings.VaultPath,
		VaultKVVersion: settings.VaultKVVersion,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	})
}
