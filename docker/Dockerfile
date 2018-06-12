FROM alpine:edge

COPY build.sh /build.sh
RUN /build.sh

EXPOSE 8096

ENV PUID=1000
ENV PGID=1000

VOLUME /config
VOLUME /media

HEALTHCHECK CMD wget -q http://localhost:8096/swagger -O /dev/null || exit 1

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
