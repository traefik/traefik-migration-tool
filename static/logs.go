package static

import "github.com/containous/traefik/v2/pkg/types"

func migrateAccessLog(oldCfg Configuration) *types.AccessLog {
	if oldCfg.AccessLog == nil {
		return nil
	}

	return &types.AccessLog{
		FilePath:      oldCfg.AccessLog.File,
		Format:        oldCfg.AccessLog.Format,
		Filters:       migrateAccessLogFilters(oldCfg),
		Fields:        migrateAccessLogFields(oldCfg),
		BufferingSize: oldCfg.AccessLog.BufferingSize,
	}
}

func migrateAccessLogFields(oldCfg Configuration) *types.AccessLogFields {
	if oldCfg.AccessLog.Fields == nil {
		return nil
	}

	return &types.AccessLogFields{
		DefaultMode: oldCfg.AccessLog.Fields.DefaultMode,
		Names:       oldCfg.AccessLog.Fields.Names,
		Headers:     migrateFieldHeaders(oldCfg),
	}
}

func migrateFieldHeaders(oldCfg Configuration) *types.FieldHeaders {
	if oldCfg.AccessLog.Fields.Headers == nil {
		return nil
	}

	return &types.FieldHeaders{
		DefaultMode: oldCfg.AccessLog.Fields.Headers.DefaultMode,
		Names:       oldCfg.AccessLog.Fields.Headers.Names,
	}
}

func migrateAccessLogFilters(oldCfg Configuration) *types.AccessLogFilters {
	if oldCfg.AccessLog.Filters == nil {
		return nil
	}

	return &types.AccessLogFilters{
		StatusCodes:   oldCfg.AccessLog.Filters.StatusCodes,
		RetryAttempts: oldCfg.AccessLog.Filters.RetryAttempts,
		MinDuration:   convertDuration(oldCfg.AccessLog.Filters.Duration, 0),
	}
}

func migrateTraefikLog(oldCfg Configuration) *types.TraefikLog {
	logCfg := &types.TraefikLog{
		Level: oldCfg.LogLevel,
	}

	if oldCfg.TraefikLog != nil {
		logCfg.FilePath = oldCfg.TraefikLog.File
		logCfg.Format = oldCfg.TraefikLog.Format
	}
	return logCfg
}
