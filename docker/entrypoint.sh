#!/bin/sh
chown $PUID:$PGID /config /media
su-exec $PUID:$PGID \
    mono /emby/MediaBrowser.Server.Mono.exe \
    -programdata /config \
    -ffmpeg /usr/bin/ffmpeg \
    -ffprobe /usr/bin/ffprobe
