package static

import (
	"log"
	"time"

	"github.com/traefik/traefik/v2/pkg/types"
)

func migrateMetrics(oldCfg Configuration) *types.Metrics {
	if oldCfg.Metrics == nil {
		return nil
	}

	return &types.Metrics{
		Prometheus: migratePrometheus(oldCfg),
		Datadog:    migrateDatadog(oldCfg),
		StatsD:     migrateStatsD(oldCfg),
		InfluxDB:   migrateInfluxDB(oldCfg),
	}
}

func migrateInfluxDB(oldCfg Configuration) *types.InfluxDB {
	if oldCfg.Metrics.InfluxDB == nil {
		return nil
	}

	return &types.InfluxDB{
		Address:              oldCfg.Metrics.InfluxDB.Address,
		Protocol:             oldCfg.Metrics.InfluxDB.Protocol,
		PushInterval:         parsePushInterval(oldCfg.Metrics.InfluxDB.PushInterval),
		Database:             oldCfg.Metrics.InfluxDB.Database,
		RetentionPolicy:      oldCfg.Metrics.InfluxDB.RetentionPolicy,
		Username:             "",
		Password:             "",
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migrateStatsD(oldCfg Configuration) *types.Statsd {
	if oldCfg.Metrics.StatsD == nil {
		return nil
	}

	return &types.Statsd{
		Address:              oldCfg.Metrics.StatsD.Address,
		PushInterval:         parsePushInterval(oldCfg.Metrics.StatsD.PushInterval),
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migrateDatadog(oldCfg Configuration) *types.Datadog {
	if oldCfg.Metrics.Datadog == nil {
		return nil
	}

	return &types.Datadog{
		Address:              oldCfg.Metrics.Datadog.Address,
		PushInterval:         parsePushInterval(oldCfg.Metrics.Datadog.PushInterval),
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migratePrometheus(oldCfg Configuration) *types.Prometheus {
	if oldCfg.Metrics.Prometheus == nil {
		return nil
	}

	return &types.Prometheus{
		Buckets:              oldCfg.Metrics.Prometheus.Buckets,
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
		EntryPoint:           oldCfg.Metrics.Prometheus.EntryPoint,
	}
}

func parsePushInterval(value string) types.Duration {
	if value == "" {
		return types.Duration(10 * time.Second)
	}

	pushInternal, err := time.ParseDuration(value)
	if err != nil {
		log.Fatal(err)
	}

	return types.Duration(pushInternal)
}
