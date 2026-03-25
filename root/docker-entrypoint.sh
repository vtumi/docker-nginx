#!/bin/sh
set -e

# Start totp_auth via spawn-fcgi
spawn-fcgi -n -u nginx -s /var/run/nginx-auth/sock -M 666 \
    /usr/bin/nginx-auth /etc/nginx/nginx-auth.conf &

# Start nginx
exec /usr/sbin/nginx -g "daemon off;"
