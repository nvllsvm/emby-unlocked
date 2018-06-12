FROM alpine:edge
RUN apk add  --no-cache  --update curl

COPY build.sh /build.sh
RUN /build.sh

EXPOSE 8096

ENV PUID=1000
ENV PGID=1000

VOLUME /config
VOLUME /media

COPY entrypoint.sh /entrypoint.sh
HEALTHCHECK --interval=15s --timeout=15s --start-period=20s CMD curl -f http://localhost:8096/emby/system/info/public?format=json || exit 1
ENTRYPOINT ["/entrypoint.sh"]
