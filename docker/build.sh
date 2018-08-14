#!/bin/sh
set -ex

BUILD_DIR=/build
EMBY_DIR=/emby

install_dependencies() {
    # Testing repo for Mono
    echo http://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories

    apk upgrade

    # Build deps
    apk add -t .dev git ffmpeg-dev mono-dev binutils curl icu libunwind openssl bash zip

    # Run deps
    apk add ffmpeg mono sqlite imagemagick-dev sqlite-dev su-exec
}


cleanup_dependencies() {
    apk del --purge -t .dev
}


build_msbuild() {
    git clone --depth 1 https://github.com/Microsoft/msbuild.git
    set +e
    ./msbuild/build/build.sh
    ./msbuild/build/build.sh -hostType mono
    set -e
}


build_emby() {
    git clone --depth 1 https://github.com/MediaBrowser/Emby
    git clone --depth 1 https://github.com/nvllsvm/emby-unlocked

    patch -N -p1 \
        Emby/Emby.Server.Implementations/Security/PluginSecurityManager.cs \
        emby-unlocked/patches/PluginSecurityManager.cs.patch

    msbuild/artifacts/mono-msbuild/msbuild \
        /p:Configuration='Release Mono' \
        /p:Platform='Any CPU' \
        /p:OutputPath="$EMBY_DIR" \
        /t:build Emby/MediaBrowser.sln
    mono --aot='full' -O='all' "$EMBY_DIR"/MediaBrowser.Server.Mono.exe

    cp emby-unlocked/replacements/connectionmanager.js \
        /emby/dashboard-ui/bower_components/emby-apiclient
}


mkdir -p "$EMBY_DIR" "$BUILD_DIR"
install_dependencies

cd "$BUILD_DIR"
build_msbuild
build_emby
cd

cleanup_dependencies
rm -rf "$BUILD_DIR" /build.sh /root /tmp /var/cache/apk/*
mkdir /root /tmp
