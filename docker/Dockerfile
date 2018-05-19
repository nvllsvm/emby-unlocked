FROM alpine:edge

COPY build.sh /build.sh
RUN /build.sh

EXPOSE 8096

ENV PUID=1000
ENV PGID=1000

VOLUME /config
VOLUME /media

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
