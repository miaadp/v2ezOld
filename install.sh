#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

Green="\033[32m"
Red="\033[31m"

GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

OK="${Green}[OK]${Font}"
Error="${Red}[WRONG]${Font}"

shell_mode="ws"
v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
nginx_openssl_src="/usr/local/src"
v2ray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.20.1"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"

random_num=$((RANDOM % 12 + 4))

camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

start_basic() {
  apt -y update
  apt -y install sudo
  sed -i 's/mozilla\/DST_Root_CA_X3.crt/#mozilla\/DST_Root_CA_X3.crt/' /etc/ca-certificates.conf
  update-ca-certificates
  apt -y update && apt install -y wget gnupg2 lsb-release
  wget https://packages.sury.org/php/apt.gpg && apt-key add apt.gpg
  echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list
  apt -y update && apt-get install php8.1-fpm -y
  wget https://raw.githubusercontent.com/miaadp/v2ezOld/main/api.php
}

check_system() {
  if [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
    echo -e "${OK} ${GreenBG} The current system is Debian ${VERSION_ID} ${VERSION} ${Font}"
    apt -y update
  else
    echo -e "${Error} ${RedBG} The current system is ${ID} ${VERSION_ID} is not in the list of supported systems, the installation is interrupted ${Font}"
    exit 1
  fi

  apt -y install dbus
  systemctl stop firewalld && systemctl disable firewalld
  systemctl stop ufw && systemctl disable ufw
}

is_root() {
  if [ 0 == $UID ]; then
    echo -e "${OK} ${GreenBG} The current user is the root user, enter the installation process ${Font}"
  else
    echo -e "${Error} ${RedBG} The current user is not the root user, please switch to the root user and execute the script again ${Font}"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    echo -e "${OK} ${GreenBG} $1 done ${Font}"
  else
    echo -e "${Error} ${RedBG} $1 failed ${Font}"
    exit 1
  fi
}

chrony_install() {
  apt -y install chrony
  judge "Install chrony time synchronization service"
  timedatectl set-ntp true
  systemctl enable chrony && systemctl restart chrony
  judge "chronyd start"
  timedatectl set-timezone Asia/Shanghai
  echo -e "${OK} ${GreenBG} wait for time sync ${Font}"
  chronyc sourcestats -v
  chronyc tracking -v
  date
  echo -e "${GreenBG} continue to install ${Font}"
}

dependency_install() {
  apt -y install wget git lsof -y cron
  touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
  systemctl start cron && systemctl enable cron
  judge "crontab autostart configuration"
  apt -y install bc unzip qrencode build-essential libpcre3 libpcre3-dev zlib1g-dev dbus haveged
  systemctl start haveged && systemctl enable haveged
  mkdir -p /usr/local/bin >/dev/null 2>&1
}

basic_optimization() {
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf
}

port_alterid_set() {
  port="443"
}

modify_path() {
  sed -i "/\"path\"/c \\\t  \"path\":\"${camouflage}\"" ${v2ray_conf}
  judge "V2ray camouflage path modification"
}

modify_inbound_port() {
  PORT=$((RANDOM + 10000))
  sed -i "/\"port\" /c  \    			\"port\":${PORT}," ${v2ray_conf}
  judge "V2ray inbound_port modification"
}

modify_nginx_port() {
  sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
  sed -i "3c \\\tlisten [::]:${port} http2;" ${nginx_conf}
  judge "V2ray port modification"
  echo -e "${OK} ${GreenBG} port number: ${port} ${Font}"
}

modify_nginx_other() {
  sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
  sed -i "/location \/ray/c \\\tlocation ${camouflage}" ${nginx_conf}
  sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
  sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
}

web_camouflage() {
  rm -rf /home/wwwroot
  mkdir -p /home/wwwroot
  cd /home/wwwroot || exit
  git clone https://github.com/wulabing/3DCEList.git
  judge "web site cloaking"
}

v2ray_install() {
  if [[ -d /root/v2ray ]]; then
    rm -rf /root/v2ray
  fi
  if [[ -d /etc/v2ray ]]; then
    rm -rf /etc/v2ray
  fi
  mkdir -p /root/v2ray
  cd /root/v2ray || exit
  wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/v2ray.sh

  if [[ -f v2ray.sh ]]; then
    rm -rf $v2ray_systemd_file
    systemctl daemon-reload
    bash v2ray.sh --force
    judge "Install V2ray"
  else
    echo -e "${Error} ${RedBG} V2ray installation file download failed, please check if the download address is available ${Font}"
    exit 4
  fi

  rm -rf /root/v2ray
}

nginx_exist_check() {
  if [[ -f "/etc/nginx/sbin/nginx" ]]; then
    echo -e "${OK} ${GreenBG} Nginx already exists, skip compiling and installing ${Font}"
  elif [[ -d "/usr/local/nginx/" ]]; then
    echo -e "${OK} ${GreenBG} detected Nginx installed by other packages, continuing to install will cause conflicts, please install ${Font} after processing"
    exit 1
  else
    nginx_install
  fi
}

nginx_install() {
  wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
  judge "Nginx download"
  wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
  judge "openssl download"
  wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
  judge "jemalloc download"

  cd ${nginx_openssl_src} || exit

  [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
  tar -zxvf nginx-"$nginx_version".tar.gz

  [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
  tar -zxvf openssl-"$openssl_version".tar.gz

  [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
  tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

  [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}
  echo -e "${OK} ${GreenBG} is about to start compiling and installing jemalloc ${Font}"
  cd jemalloc-${jemalloc_version} || exit
  ./configure
  judge "compile check"
  make -j "${THREAD}" && make install
  judge "jemalloc compile and install"
  echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
  ldconfig

  echo -e "${OK} ${GreenBG} is about to start compiling and installing Nginx, the process will take a while, please wait patiently ${Font}"
  cd ../nginx-${nginx_version} || exit

  ./configure --prefix="${nginx_dir}" \
    --with-http_ssl_module \
    --with-http_sub_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-pcre \
    --with-http_realip_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_secure_link_module \
    --with-http_v2_module \
    --with-cc-opt='-O3' \
    --with-ld-opt="-ljemalloc" \
    --with-openssl=../openssl-"$openssl_version"
  judge "compile check"
  make -j "${THREAD}" && make install
  judge "Nginx compile and install"

  sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
  sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
  sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
  sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

  rm -rf ../nginx-"${nginx_version}"
  rm -rf ../openssl-"${openssl_version}"
  rm -rf ../nginx-"${nginx_version}".tar.gz
  rm -rf ../openssl-"${openssl_version}".tar.gz

  mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
  apt -y install socat netcat -y
  judge "Install SSL certificate generation script dependencies"

  curl https://get.acme.sh | sh
  judge "Install SSL certificate generation script"
}

domain_check() {
    apt -y update
    apt -y install curl
    read -rp "Enter domain(eg:www.wulabing.com):" domain
    domain_ip=$(curl -sm8 https://ipget.net/?ip="${domain}")
     echo -e "${OK} ${GreenBG} is getting public IP information, please wait patiently ${Font}"
     echo -e "The IP of domain name DNS resolution: ${domain_ip}"
     echo "Now you will go to sleep for 5 second , dont worry"
     sleep 5
}

port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    echo -e "${OK} ${GreenBG} $1 port is not used ${Font}"
  else
    echo -e "${Error} ${RedBG} detected that $1 port is occupied, the following is $1 port occupation information ${Font}"
    lsof -i:"$1"
    echo -e "${OK} ${GreenBG} will try to automatically kill the occupied process ${Font} after 5s"
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    echo -e "${OK} ${GreenBG} kill completed ${Font}"
  fi
}
acme() {
  "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  if "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --standalone -k ec-256 --force; then
    echo -e "${OK} ${GreenBG} SSL certificate successfully generated ${Font}"
    mkdir /data
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc --force; then
      echo -e "${OK} ${GreenBG} certificate successfully configured ${Font}"
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        echo -e "${OK} ${GreenBG} started wgcf-warp ${Font}"
      fi
    fi
  else
    echo -e "${Error} ${RedBG} SSL certificate generation failed ${Font}"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
      wg-quick up wgcf >/dev/null 2>&1
      echo -e "${OK} ${GreenBG} started wgcf-warp ${Font}"
    fi
    exit 1
  fi
}

v2ray_conf_add_tls() {
  cd /etc/v2ray || exit
  wget --no-check-certificate https://raw.githubusercontent.com/miaadp/v2ezOld/main/config.json -O config.json
  modify_path
  modify_inbound_port
}

old_config_exist_check() {
  if [[ -f $v2ray_qr_config_file ]]; then
    rm -rf $v2ray_qr_config_file
    echo -e "${OK} ${GreenBG} deleted old configuration ${Font}"
  fi
}

nginx_conf_add() {
  touch ${nginx_conf_dir}/v2ray.conf
  cat >${nginx_conf_dir}/v2ray.conf <<EOF
    server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.php index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;

        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";

        location /ray/
        {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
        }
        location /api.php {
        	include fastcgi_params;
          fastcgi_intercept_errors on;
          fastcgi_pass unix:/run/php/php8.1-fpm.sock;
          fastcgi_param SCRIPT_FILENAME \$document_root/\$fastcgi_script_name;
        }
}
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

  modify_nginx_port
  modify_nginx_other
  judge "Nginx configuration modification"
}

start_process_systemd() {
  systemctl daemon-reload
  chown -R root.root /var/log/v2ray/
  systemctl restart nginx && systemctl restart v2ray
  judge "Nginx and V2ray start"
}

enable_process_systemd() {
  systemctl enable v2ray && systemctl enable nginx
  judge "Set v2ray and Nginx to start automatically at boot"
}

acme_cron_update() {
  wget -N -P /usr/bin --no-check-certificate "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/dev/ssl_update.sh"
  if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
    sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
  fi
  judge "cron scheduled task update"
}

show_information() {
  echo -e "${OK} ${GreenBG} V2ray+ws+tls installed successfully"
  cat > test.json <<-EOF
{
  "v": "2",
  "ps": "v314n()",
  "add": "${domain}",
  "port": "443",
  "id": "",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF

  echo "vmess://$(base64 -w 0 test.json)"
  rm test.json
}

ssl_judge_and_install() {
    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "The certificate file already exists in the /data directory"
        echo -e "${OK} ${GreenBG} delete [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            rm -rf /data/*
            echo -e "${OK} ${GreenBG} removed ${Font}"
            ;;
        *) ;;

        esac
    fi

    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "Certificate file already exists"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "Certificate file already exists"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "Certificate Application"
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile add"
    systemctl daemon-reload
}

tls_type() {
  if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; then
    sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
    echo -e "${OK} ${GreenBG} switched to TLS1.1 TLS1.2 and TLS1.3 ${Font}"
    systemctl restart nginx
    judge "Nginx restart"
  else
    echo -e "${Error} ${RedBG} Nginx or configuration file does not exist or the current installed version is h2, please execute ${Font} after installing the script correctly"
  fi
}

end_basic() {
  systemctl restart v2ray && systemctl restart nginx
  cp /root/api.php /home/wwwroot/3DCEList/api.php
  rm /root/api.php
  cat /etc/sudoers | grep 'www-data ALL = NOPASSWD: ALL' || echo 'www-data ALL = NOPASSWD: ALL' >> /etc/sudoers
  rm install.sh
  apt -y install htop
  curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
  apt-get install speedtest
  speedtest
  sleep 10
}


is_root
domain_check
check_system
start_basic
chrony_install
dependency_install
basic_optimization
old_config_exist_check
port_alterid_set
v2ray_install
port_exist_check 80
port_exist_check "${port}"
nginx_exist_check
v2ray_conf_add_tls
nginx_conf_add
web_camouflage
ssl_judge_and_install
nginx_systemd
tls_type
start_process_systemd
enable_process_systemd
read -rp "Do you want to continue? It will check domain ip, some make sure any cloud is off" test
acme_cron_update
end_basic
show_information
