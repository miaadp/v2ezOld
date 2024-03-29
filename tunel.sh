#!/usr/bin/env bash
show_help() {
    echo "Usage: $0 [-i DOMAIN IP PATCH] [-e IP PATCH]"
}

action=""
domain=""
ip=""
patch=""
old_text=""
new_text=""

while getopts ":i:e:" opt; do
    case $opt in
        i)
            action="install"
            domain="$OPTARG"
            ip="$3"
            patch="$4"
            ;;
        e)
            action="edit"
            old_text="$OPTARG"
            new_text="$3"
            domain="$4"
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            show_help
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            show_help
            exit 1
            ;;
    esac
done

case $action in
    install)

      echo "deb http://deb.debian.org/debian bullseye main" | sudo tee -a /etc/apt/sources.list
      echo "deb-src http://deb.debian.org/debian bullseye main" | sudo tee -a /etc/apt/sources.list

      apt update -y
      apt upgrade -y
      apt install sudo
      sudo apt install nginx certbot python3-certbot-nginx ufw -y
      ufw allow 'Nginx HTTP' & ufw allow 'Nginx HTTPS' & ufw allow 80 & ufw allow 22 & ufw allow 8080 & yes | ufw enable
      mkdir /var/www/${domain}
      chown -R $USER:$USER /var/www/${domain}

      rm -r /etc/nginx/sites-available/${domain}
      rm -r /etc/nginx/sites-enabled/${domain}

      bash -c "echo 'server {
    listen 8080;
    server_name ${domain} www.${domain};
    root /var/www/${domain};
    index index.php index.html index.htm;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location /${patch}/ {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_buffering    off;
        proxy_buffer_size  128k;
        proxy_buffers 100  128k;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$http_host;
        proxy_pass http://${ip}:8080/${patch}/;
    }
    location ~ /\.ht {
        deny all;
    }
}
server {
    if (\$host = ${domain}) {
        return 301 https://\$host\$request_uri;
    }
    listen 80;
    server_name ${domain} www.${domain};
    return 404; # managed by Certbot
}' >> /etc/nginx/sites-available/${domain}"

      rm -r /etc/nginx/nginx.conf
      bash -c "echo 'user www-data;
worker_processes 2;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 8096;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}' >> /etc/nginx/nginx.conf"

      ln -s /etc/nginx/sites-available/${domain} /etc/nginx/sites-enabled/
      unlink /etc/nginx/sites-enabled/default
      sed -i 's/try_files  \/ =404;/try_files $uri $uri\/ =404;/' /etc/nginx/sites-available/${domain}
      systemctl stop nginx
      certbot certonly --standalone -d ${domain} -d ${domain} --email amir2222@gmail.com --agree-tos --non-interactive
      systemctl start nginx
        ;;
    edit)
    sed -i "s/${old_text}/${new_text}/g" /etc/nginx/sites-available/${domain}
    echo "successfully changed"
        ;;
    *)
        echo "Unknown action: $action"
        show_help
        exit 1
        ;;
esac
