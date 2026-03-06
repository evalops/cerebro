package events

import "testing"

func TestConsumerConfigWithDefaults(t *testing.T) {
	cfg := (ConsumerConfig{}).withDefaults()
	if len(cfg.URLs) == 0 {
		t.Fatal("expected default URL")
	}
	if cfg.Stream == "" || cfg.Subject == "" || cfg.Durable == "" {
		t.Fatal("expected default stream/subject/durable")
	}
	if cfg.BatchSize <= 0 || cfg.AckWait <= 0 || cfg.FetchTimeout <= 0 {
		t.Fatal("expected positive default batch/ack/fetch settings")
	}
}

func TestConsumerConfigValidate(t *testing.T) {
	valid := (ConsumerConfig{
		URLs:         []string{"nats://127.0.0.1:4222"},
		Stream:       "ENSEMBLE_TAP",
		Subject:      "ensemble.tap.>",
		Durable:      "cerebro_graph_builder",
		BatchSize:    10,
		AckWait:      5,
		FetchTimeout: 5,
	}).withDefaults()
	if err := valid.validate(); err != nil {
		t.Fatalf("expected config to validate: %v", err)
	}

	invalid := ConsumerConfig{
		URLs:      []string{"nats://127.0.0.1:4222"},
		Stream:    "ENSEMBLE_TAP",
		Subject:   "ensemble.tap.>",
		Durable:   "cerebro_graph_builder",
		BatchSize: 0,
	}
	if err := invalid.validate(); err == nil {
		t.Fatal("expected validation error for invalid batch size")
	}
}
