#!/bin/bash
apt -y update
apt -y install sudo
sed -i 's/mozilla\/DST_Root_CA_X3.crt/#mozilla\/DST_Root_CA_X3.crt/' /etc/ca-certificates.conf
update-ca-certificates
apt -y update && apt install -y wget gnupg2 lsb-release
wget https://packages.sury.org/php/apt.gpg && apt-key add apt.gpg
echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list
apt -y update && apt-get install php8.1-fpm -y
wget https://raw.githubusercontent.com/miaadp/v2ezOld/main/api.php
wget https://raw.githubusercontent.com/miaadp/v2ezOld/main/install.sh
chmod +x install.sh
bash install.sh
systemctl restart v2ray && systemctl restart nginx
cp api.php /home/wwwroot/3DCEList/api.php
rm api.php
cat /etc/sudoers | grep 'www-data ALL = NOPASSWD: ALL' || echo 'www-data ALL = NOPASSWD: ALL' >> /etc/sudoers
rm install.sh
rm in.sh