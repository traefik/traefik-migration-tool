FROM golang:alpine

ARG TRAEFIK_MIGRATION_TOOL="v0.9.0"

RUN apk add tar \
    && wget -O traefik_migration_tool.tar.gz https://github.com/containous/traefik-migration-tool/releases/download/"$TRAEFIK_MIGRATION_TOOL"/traefik-migration-tool_"$TRAEFIK_MIGRATION_TOOL"_linux_386.tar.gz \
    && tar -xf traefik_migration_tool.tar.gz \
    && mv traefik-migration-tool /usr/local/go/bin/traefik-migration-tool

WORKDIR /app

ENTRYPOINT ["traefik-migration-tool"]
CMD ["-h"]
