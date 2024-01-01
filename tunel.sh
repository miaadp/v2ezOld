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
      apt update -y
      apt upgrade -y
      apt install sudo nginx certbot python3-certbot-nginx ufw -y
      ufw allow 'Nginx HTTP' ufw allow 'Nginx HTTPS' ufw enable -n
      mkdir /var/www/${domain}
      chown -R $USER:$USER /var/www/${domain}

      bash -c "echo 'server {
        server {
            listen 443 ssl; # managed by Certbot
            server_name ${domain} www.${domain};
            root /var/www/${domain};
        
            index index.php index.html index.htm;
        
          location / {
              try_files \$uri \$uri/ =404;
          }
        
          location /${patch}/
          {
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
              proxy_set_header Early-Data \$ssl_early_data;
              proxy_pass https://${ip}:443/${patch}/;
          }
        
            location ~ /\.ht {
                deny all;
            }

            ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
            include /etc/letsencrypt/options-ssl-nginx.conf;
            ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
        }
        server {
            listen 8080;
            server_name ${domain} www.${domain};
            root /var/www/${domain};
        
            index index.php index.html index.htm;
        
            location / {
                try_files $uri $uri/ =404;
            }
        
          location /${patch}/
          {
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
              proxy_set_header Early-Data \$ssl_early_data;
              proxy_pass https://${ip}:443/${patch}/;
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
        }

      }' >> /etc/nginx/sites-available/${domain}"

      ln -s /etc/nginx/sites-available/${domain} /etc/nginx/sites-enabled/
      unlink /etc/nginx/sites-enabled/default
      sed -i 's/try_files  \/ =404;/try_files $uri $uri\/ =404;/' /etc/nginx/sites-available/${domain}
      systemctl reload nginx
      certbot certonly --standalone -d ${domain} -d www.${domain} --email amir2222@gmail.com --agree-tos --non-interactive
      systemctl reload nginx
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
