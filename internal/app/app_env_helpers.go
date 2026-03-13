package app

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/apiauth"
	"github.com/evalops/cerebro/internal/envutil"
	"github.com/evalops/cerebro/internal/secretsource"
)

var configValueSourceState struct {
	mu     sync.RWMutex
	source secretsource.Source
}

var credentialSourceExactKeys = map[string]struct{}{
	"API_KEYS":              {},
	"API_CREDENTIALS_JSON":  {},
	"PAGERDUTY_ROUTING_KEY": {},
}

var credentialSourceKeySuffixes = []string{
	"_API_KEY",
	"_API_TOKEN",
	"_TOKEN",
	"_SECRET",
	"_SECRET_KEY",
	"_PASSWORD",
	"_PRIVATE_KEY",
	"_SIGNING_KEY",
	"_NKEY_SEED",
	"_USER_JWT",
	"_WEBHOOK_URL",
	"_ROUTING_KEY",
	"_CREDENTIALS_JSON",
}

func getEnv(key, fallback string) string {
	if credentialSourceEligibleKey(key) {
		if value, ok := lookupActiveConfigSourceValue(key); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	if value, ok := lookupRawConfigValue(key); ok {
		return value
	}
	return fallback
}

func credentialSourceEligibleKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	if _, ok := credentialSourceExactKeys[key]; ok {
		return true
	}
	for _, suffix := range credentialSourceKeySuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func withConfigValueSource(source secretsource.Source, fn func()) {
	configValueSourceState.mu.Lock()
	previous := configValueSourceState.source
	configValueSourceState.source = source
	configValueSourceState.mu.Unlock()
	defer func() {
		configValueSourceState.mu.Lock()
		configValueSourceState.source = previous
		configValueSourceState.mu.Unlock()
	}()
	fn()
}

func lookupActiveConfigSourceValue(key string) (string, bool) {
	configValueSourceState.mu.RLock()
	source := configValueSourceState.source
	configValueSourceState.mu.RUnlock()
	if source == nil {
		return "", false
	}
	return source.Lookup(key)
}

func lookupRawConfigValue(key string) (string, bool) {
	if value := strings.TrimSpace(envutil.Get(key, "")); value != "" {
		return value, true
	}
	if value, ok := lookupConfigFileValue(key); ok {
		return value, true
	}
	return "", false
}

func bootstrapConfigValue(key, fallback string) string {
	if value, ok := lookupRawConfigValue(key); ok {
		return value
	}
	return fallback
}

func bootstrapConfigInt(key string, fallback int) int {
	value := strings.TrimSpace(bootstrapConfigValue(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		recordConfigProblem("%s must be a valid integer", key)
		return fallback
	}
	return parsed
}

var configParseRecorder struct {
	mu       sync.Mutex
	problems *[]string
}

func withConfigParseRecorder(fn func()) []string {
	configParseRecorder.mu.Lock()
	defer configParseRecorder.mu.Unlock()

	problems := make([]string, 0)
	configParseRecorder.problems = &problems
	defer func() {
		configParseRecorder.problems = nil
	}()

	fn()
	return normalizeConfigProblems(problems)
}

func recordConfigProblem(format string, args ...any) {
	if configParseRecorder.problems == nil {
		return
	}
	*configParseRecorder.problems = append(*configParseRecorder.problems, fmt.Sprintf(format, args...))
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		recordConfigProblem("%s must be a valid integer", key)
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(getEnv(key, "")))
	if value == "" {
		return fallback
	}
	switch value {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		recordConfigProblem("%s must be a valid boolean", key)
		return fallback
	}
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		recordConfigProblem("%s must be a valid duration", key)
		return fallback
	}
	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(getEnv(key, ""))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		recordConfigProblem("%s must be a valid number", key)
		return fallback
	}
	return parsed
}

func parseKeyValueCSV(value string) map[string]string {
	parsed := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			continue
		}
		parsed[key] = val
	}
	return parsed
}

func parseAPIKeys(value string) map[string]string {
	keys := make(map[string]string)
	if value == "" {
		return keys
	}

	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 1 {
			parts = strings.SplitN(entry, "=", 2)
		}

		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}

		userID := ""
		if len(parts) == 2 {
			userID = strings.TrimSpace(parts[1])
		}
		if userID == "" {
			userID = defaultAPIUserID(key)
		}
		keys[key] = userID
	}

	return keys
}

func defaultAPIUserID(key string) string {
	return apiauth.DefaultUserIDForKey(key)
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func splitCSV(s string) []string {
	var result []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

func parseDurationEnvMap(prefix string) map[string]time.Duration {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil
	}
	out := make(map[string]time.Duration)
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			recordConfigProblem("%s must be a valid duration", key)
			continue
		}
		suffix := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(key, prefix)))
		if suffix == "" {
			continue
		}
		out[suffix] = duration
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// defaultScanTables returns the comprehensive list of tables to scan

func normalizePrivateKey(value string) string {
	return envutil.NormalizePrivateKey(value)
}
