Emby with Emby Premiere features unlocked.

# Environment Variables

**Optional**
- ``PUID`` - User ID to run as (default 1000)
- ``PGID`` - Group ID to run as (default 1000)

# Volumes

- ``/config`` - Emby configuration
- ``/media`` - Media

# Ports

- ``8096`` - API and web UI

# Usage

```
$ docker run \
    -e PUID=1000 \
    -e PGID=1000 \
    -p 8096:8096 \
    -v /host/config:/config \
    -v /host/media:/media \
    nvllsvm/emby-unlocked
```
