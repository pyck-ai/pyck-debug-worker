# netcheck endpoint host

A dedicated target for `--netcheck-hosts` on a plain Ubuntu VM (e.g. a Hetzner VM
in Singapore). It serves only the 1 MiB payload at `/static/netcheck/1m.bin` over
TLS + HTTP/2. Everything else returns 404.

Prerequisites: an unproxied A record at Cloudflare (e.g. `region-sing.pyck.cloud`)
pointing at the VM, and only port 443 open inbound (plus SSH for setup).

## Install

Run as root on the VM, with `netcheck.conf` copied to `/tmp/netcheck.conf`:

```sh
apt-get update && apt-get install -y nginx curl openssl

# Payload: the same bytes the pyck frontend serves.
install -d /var/www/netcheck/static/netcheck
curl -fsSL -o /var/www/netcheck/static/netcheck/1m.bin \
  https://dev.pyck.cloud/static/netcheck/1m.bin
echo "77cfe40391956e62e2d057912f0c9fbb07360ea8e3ba9576949ba0e4f8ca929e  /var/www/netcheck/static/netcheck/1m.bin" | sha256sum -c

# Self-signed certificate; the worker does not verify it.
install -d -m 700 /etc/nginx/netcheck
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$(hostname -f)" \
  -keyout /etc/nginx/netcheck/key.pem -out /etc/nginx/netcheck/cert.pem

install -m 644 /tmp/netcheck.conf /etc/nginx/sites-available/netcheck
ln -sf /etc/nginx/sites-available/netcheck /etc/nginx/sites-enabled/netcheck
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

## Verify

```sh
curl -sk -o /dev/null -w '%{http_code} %{size_download} %{http_version}\n' \
  https://<host>/static/netcheck/1m.bin   # 200 1048576 2
curl -sk -o /dev/null -w '%{http_code}\n' https://<host>/   # 404
```
