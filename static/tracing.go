package static

import (
	"github.com/containous/traefik/v2/pkg/config/static"
	"github.com/containous/traefik/v2/pkg/tracing/datadog"
	"github.com/containous/traefik/v2/pkg/tracing/jaeger"
	"github.com/containous/traefik/v2/pkg/tracing/zipkin"
)

func migrateTracing(oldCfg Configuration) *static.Tracing {
	if oldCfg.Tracing == nil {
		return nil
	}

	return &static.Tracing{
		ServiceName:   oldCfg.Tracing.ServiceName,
		SpanNameLimit: oldCfg.Tracing.SpanNameLimit,
		Jaeger:        migrateJaeger(oldCfg),
		Zipkin:        migrateZipkin(oldCfg),
		Datadog:       migrateDatadogTracing(oldCfg),
		Instana:       nil, // SKIP
		Haystack:      nil, // SKIP
	}
}

func migrateJaeger(oldCfg Configuration) *jaeger.Config {
	if oldCfg.Tracing.Jaeger == nil {
		return nil
	}

	return &jaeger.Config{
		SamplingServerURL:      oldCfg.Tracing.Jaeger.SamplingServerURL,
		SamplingType:           oldCfg.Tracing.Jaeger.SamplingType,
		SamplingParam:          oldCfg.Tracing.Jaeger.SamplingParam,
		LocalAgentHostPort:     oldCfg.Tracing.Jaeger.LocalAgentHostPort,
		Gen128Bit:              false, // SKIP
		Propagation:            "",    // SKIP
		TraceContextHeaderName: oldCfg.Tracing.Jaeger.TraceContextHeaderName,
		Collector:              nil, // SKIP
	}
}

func migrateZipkin(oldCfg Configuration) *zipkin.Config {
	if oldCfg.Tracing.Zipkin == nil {
		return nil
	}

	return &zipkin.Config{
		HTTPEndpoint: oldCfg.Tracing.Zipkin.HTTPEndpoint,
		SameSpan:     oldCfg.Tracing.Zipkin.SameSpan,
		ID128Bit:     oldCfg.Tracing.Zipkin.ID128Bit,
		SampleRate:   0, // SKIP
	}
}

func migrateDatadogTracing(oldCfg Configuration) *datadog.Config {
	if oldCfg.Tracing.DataDog == nil {
		return nil
	}

	return &datadog.Config{
		LocalAgentHostPort:         oldCfg.Tracing.DataDog.LocalAgentHostPort,
		GlobalTag:                  oldCfg.Tracing.DataDog.GlobalTag,
		Debug:                      oldCfg.Tracing.DataDog.Debug,
		PrioritySampling:           oldCfg.Tracing.DataDog.PrioritySampling,
		TraceIDHeaderName:          oldCfg.Tracing.DataDog.TraceIDHeaderName,
		ParentIDHeaderName:         oldCfg.Tracing.DataDog.ParentIDHeaderName,
		SamplingPriorityHeaderName: oldCfg.Tracing.DataDog.SamplingPriorityHeaderName,
		BagagePrefixHeaderName:     oldCfg.Tracing.DataDog.BagagePrefixHeaderName,
	}
}
