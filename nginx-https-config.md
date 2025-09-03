1. Install Nginx + Certbot (if not already)

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

2. Create a single vhost file (HTTP only for now; Certbot will add HTTPS)

```bash
sudo tee /etc/nginx/conf.d/monitoring.conf > /dev/null <<'NGINX'
# Grafana (port 3000)
server {
    listen 80;
    listen [::]:80;
    server_name grafana.thakurprince.com;

    location / {
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        "upgrade";
        proxy_pass http://127.0.0.1:3000;
    }
}

# Alertmanager (port 9093)
server {
    listen 80;
    listen [::]:80;
    server_name alerts.thakurprince.com;

    location / {
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://127.0.0.1:8000;
    }
}
NGINX

sudo nginx -t && sudo systemctl reload nginx
```

3. Get Let’s Encrypt certs and let Certbot auto-edit Nginx to HTTPS

```bash
# Make sure Cloudflare is set to DNS only (grey cloud) during this step
sudo certbot --nginx -d grafana.thakurprince.com -d alerts.thakurprince.com
```

Certbot will:

* obtain certificates,
* add the SSL blocks,
* and set up HTTP→HTTPS redirects automatically.

4. (Optional) If you *do* want the `sites-available/sites-enabled` layout instead:

```bash
sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
# Ensure nginx.conf includes sites-enabled:
# it should contain:  include /etc/nginx/sites-enabled/*;
# then put your file in sites-available and symlink it:
sudo ln -s /etc/nginx/sites-available/monitoring /etc/nginx/sites-enabled/monitoring
sudo nginx -t && sudo systemctl reload nginx
```

Quick checklist

* DNS: `grafana.thakurprince.com` and `alerts.thakurprince.com` point to your server’s public IP.
* Firewall/NSG: 80 & 443 open.
* Services: Grafana on `127.0.0.1:3000`, Alertmanager on `127.0.0.1:8000`.

If you paste the commands above as-is, you won’t need `/etc/nginx/sites-available/monitoring` at all.
