# netcheck endpoint host

A dedicated target for `--netcheck-hosts` on a plain Ubuntu VM (e.g. a Hetzner VM
in Singapore). It serves only the 1 MiB payload at `/static/netcheck/1m.bin` over
TLS + HTTP/2 with a Let's Encrypt certificate, so the worker can verify it and
detect TLS-intercepting middleboxes. Everything else returns 404.

Prerequisites: an unproxied A record at Cloudflare (e.g. `region-sing.pyck.cloud`)
pointing at the VM, and ports 443 and 80 open inbound (80 only serves the Let's
Encrypt validation and renewal), plus SSH for setup.

## Install

Run as root on the VM, with `netcheck.conf` copied to `/tmp/netcheck.conf`:

```sh
export HOST=region-sing.pyck.cloud   # this VM's hostname
apt-get update && apt-get install -y nginx certbot curl openssl

# Payload: the same bytes the pyck frontend serves.
install -d /var/www/netcheck/static/netcheck /var/www/letsencrypt
curl -fsSL -o /var/www/netcheck/static/netcheck/1m.bin \
  https://dev.pyck.cloud/static/netcheck/1m.bin
echo "77cfe40391956e62e2d057912f0c9fbb07360ea8e3ba9576949ba0e4f8ca929e  /var/www/netcheck/static/netcheck/1m.bin" | sha256sum -c

# Temporary self-signed certificate so nginx can start; replaced below.
install -d -m 700 /etc/nginx/netcheck
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$HOST" \
  -keyout /etc/nginx/netcheck/key.pem -out /etc/nginx/netcheck/cert.pem

install -m 644 /tmp/netcheck.conf /etc/nginx/sites-available/netcheck
ln -sf /etc/nginx/sites-available/netcheck /etc/nginx/sites-enabled/netcheck
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Let's Encrypt (HTTP-01 via port 80); renewal runs from certbot's systemd timer.
certbot certonly -n --agree-tos --register-unsafely-without-email \
  --webroot -w /var/www/letsencrypt -d "$HOST" --deploy-hook "systemctl reload nginx"
ln -sf /etc/letsencrypt/live/$HOST/fullchain.pem /etc/nginx/netcheck/cert.pem
ln -sf /etc/letsencrypt/live/$HOST/privkey.pem /etc/nginx/netcheck/key.pem
nginx -t && systemctl reload nginx
certbot renew --dry-run

# If ufw is active:
ufw allow 80/tcp && ufw allow 443/tcp
```

## Verify

```sh
curl -s -o /dev/null -w '%{http_code} %{size_download} %{http_version}\n' \
  https://<host>/static/netcheck/1m.bin   # 200 1048576 2, no -k needed
curl -s -o /dev/null -w '%{http_code}\n' https://<host>/   # 404
```
