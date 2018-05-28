#!/bin/sh
set -ex

EMBY_VERSION=3.4.1.0

# Testing repo for Mono
echo http://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories

apk update
apk upgrade

# Build deps
apk add git ffmpeg-dev mono-dev binutils

# Run deps
apk add ffmpeg mono sqlite imagemagick-dev sqlite-dev su-exec

mkdir /build

# install referenceassemblies-pcl
cd /build
git clone https://github.com/directhex/xamarin-referenceassemblies-pcl
cd xamarin-referenceassemblies-pcl
install -dm 755 /usr/lib/mono/xbuild-frameworks/.NETPortable/
cp -dr v4.5 /usr/lib/mono/xbuild-frameworks/.NETPortable/

# build and install emby
cd /build
git clone https://github.com/MediaBrowser/Emby Emby

# Workaround for incorrect tag https://github.com/MediaBrowser/Emby/issues/3299
#git -C Emby checkout $EMBY_VERSION
git -C Emby checkout e4f1a16550f7d497968d19683812e594785fbcd9

git clone https://github.com/nvllsvm/emby-unlocked emby-unlocked
git -C emby-unlocked checkout $EMBY_VERSION


#export TERM=xterm
mkdir /emby
cd /build/Emby
patch -N -p1 Emby.Server.Implementations/Security/PluginSecurityManager.cs \
    ../emby-unlocked/patches/PluginSecurityManager.cs.patch

xbuild \
    /p:Configuration='Release Mono' \
    /p:Platform='Any CPU' \
    /p:OutputPath='/emby' \
    /t:build MediaBrowser.sln
find / -name 'MediaBrowser.Server.Mono.exe'
mono --aot='full' -O='all' /emby/MediaBrowser.Server.Mono.exe

cp ../emby-unlocked/replacements/connectionmanager.js \
    /emby/dashboard-ui/bower_components/emby-apiclient

cd /
rm -rf /build

# Remove build deps
apk del git ffmpeg-dev mono-dev binutils
