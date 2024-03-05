<?php
$user = 'v314nSudo';
$pass = 'v314nSudoPassword@13498234';
$serverIP = '108.181.126.147';
function show ($status, $data) {
    header('Content-type: application/json;');
    echo json_encode(['ok' => $status, 'data' => $data], 448);
}

if (isset($_GET['type']) && isset($_GET['user']) && isset($_GET['pass']) && $_GET['user'] === $user && $_GET['pass'] === $pass) {
    if (isset($_GET['type']) && $_GET['type'] == 'update') {
        shell_exec('sudo chmod -R 777 /home/wwwroot/3DCEList/api.php');
        copy('https://raw.githubusercontent.com/miaadp/v2ezOld/main/api.php', '/home/wwwroot/3DCEList/api.php');
        show(true, 'done');
        exit();
    }
    $ip = $_SERVER["HTTP_CF_CONNECTING_IP"] ?? $_SERVER['HTTP_AR_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'];
    if ($ip != $serverIP) {
        show(false, 'who are you? ' . $ip);
        exit();
    }
    switch ($_GET['type']) {
        case 'no_tls' :
            $address_conf = '/etc/nginx/conf/conf.d/v2ray.conf';
            $path = shell_exec("awk '/location \\/[a-zA-Z0-9]+\\// {print $2; exit}' $address_conf");
            $domain = shell_exec("awk '/server_name [a-zA-Z0-9.-]+;/ {print $2; exit}' $address_conf");
            $port = shell_exec("grep -oP 'proxy_pass http://127.0.0.1:\\K\\d+' $address_conf");
            shell_exec('sudo chown www-data:www-data /etc/nginx/conf/conf.d/v2ray.conf');
            $domain = trim(str_replace(["\r", "\n", ' ', ';'], '', $domain));
            $path = trim(str_replace(["\r", "\n", ' ', '{'], '', $path));
            $port = trim(str_replace(["\r", "\n", ' '], '', $port));
            $conf = 'server {
  listen 8080;
  server_name DOMAIN;
        index index.php index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;

  location PATH{
        proxy_redirect off;
        proxy_read_timeout 1200s;
  proxy_pass http://127.0.0.1:PORT;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        }
        location /api.php {
          include fastcgi_params;
          fastcgi_intercept_errors on;
          fastcgi_pass unix:/run/php/php8.1-fpm.sock;
          fastcgi_param SCRIPT_FILENAME $document_root/$fastcgi_script_name;
        }
}
    server {
        listen 80;
        listen [::]:80;
  server_name DOMAIN;
  return 301 https://DOMAIN$request_uri;
    }';
            $final_conf = str_replace(['DOMAIN', 'PATH', 'PORT'], [$domain, $path, $port], $conf);
            file_put_contents($address_conf, $final_conf);
            shell_exec('sudo systemctl restart nginx');
            show(true, "OK");
            break;
        case 'true_tls':
            $address_conf = '/etc/nginx/conf/conf.d/v2ray.conf';
            $path = shell_exec("awk '/location \\/[a-zA-Z0-9]+\\// {print $2; exit}' $address_conf");
            $domain = shell_exec("awk '/server_name [a-zA-Z0-9.-]+;/ {print $2; exit}' $address_conf");
            $port = shell_exec("grep -oP 'proxy_pass http://127.0.0.1:\\K\\d+' $address_conf");
            shell_exec('sudo chown www-data:www-data /etc/nginx/conf/conf.d/v2ray.conf');
            $domain = trim(str_replace(["\r", "\n", ' ', ';'], '', $domain));
            $path = trim(str_replace(["\r", "\n", ' ', '{'], '', $path));
            $port = trim(str_replace(["\r", "\n", ' '], '', $port));
            $conf = 'server{
            listen 8080;
            server_name DOMAIN;
            index index.php index.html index.htm;
            root  /home/wwwroot/3DCEList;
            error_page 400 = /400.html;

            location ~ \.php {
            include fastcgi_params;
            fastcgi_intercept_errors on;
            fastcgi_pass unix:/run/php/php8.1-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root/$fastcgi_script_name;
            }
            }
        server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           DOMAIN;
        index index.php index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;

        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";

        location PATH
        {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_pass http://127.0.0.1:PORT;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data $ssl_early_data;
        }
        location /api.php {
        	include fastcgi_params;
          fastcgi_intercept_errors on;
          fastcgi_pass unix:/run/php/php8.1-fpm.sock;
          fastcgi_param SCRIPT_FILENAME $document_root/$fastcgi_script_name;
        }
}
    server {
        listen 80;
        listen [::]:80;
        server_name DOMAIN;
        return 301 https://DOMAIN$request_uri;
    }';
            $final_conf = str_replace(['DOMAIN', 'PATH', 'PORT'], [$domain, $path, $port], $conf);
            file_put_contents($address_conf, $final_conf);
            shell_exec('sudo systemctl restart nginx');
            show(true, "OK");
            break;
        case 'save':
            $adds = $_POST['add'] ?? [];
            $removes = $_POST['remove'] ?? [];
            $config = json_decode(file_get_contents('/etc/v2ray/config.json'), true);
            $config2 = $config;
            foreach ($config['inbounds'] as &$inbound) {
                if (isset($inbound['port']) && $inbound['port'] == 10085) {
                    continue;
                }
                $protocol = match ($inbound['protocol']) {
                    'trojan' => 'password',
                    default => 'id'
                };
                $uuids_co = array_column($inbound['settings']['clients'], $protocol);
                if (!empty($removes)) {
                    if (is_string($removes) && $removes == 'remove_all') {
                        $inbound['settings']['clients'] = [];
                    }
                    else {
                        foreach ($removes as $value) {
                            if (in_array($value, $uuids_co)) {
                                unset($inbound['settings']['clients'][array_search($value, $uuids_co)]);
                            }
                        }
                    }
                }
                if (!empty($adds)) {
                    foreach ($adds as $value) {
                        if (!in_array($value, $uuids_co)) {
                            if ($protocol == 'password') {
                                $inbound['settings']['clients'][] = [
                                    'password' => $value,
                                    'email'    => str_replace('-', '', $value),
                                ];
                            }
                            else {
                                $inbound['settings']['clients'][] = [
                                    'id'    => $value,
                                    'email' => str_replace('-', '', $value),
                                    'level' => 0,
                                ];
                            }
                        }
                    }
                }
                sort($inbound['settings']['clients']);
            }
            if ($config2 !== $config) {
                shell_exec('sudo chmod 777 /etc/v2ray/config.json');
                $x = str_replace([
                    '"settings":[],',
                    '"stats":[]',
                    '"levels":[{"statsUserUplink":true,"statsUserDownlink":true}],',
                ], [
                    '"settings":{},',
                    '"stats":{}',
                    '"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}},',
                ], json_encode($config));
                file_put_contents('/etc/v2ray/config.json', $x);
                if (!isset($_GET['no_restart'])) {
                    shell_exec('sudo systemctl restart v2ray');
                }
                show(true, 'done');
            }
            else {
                show(true, 'nothing changed');
            }
            break;
        case 'change_protocol':
            if (isset($_POST['name'])) {
                $protocol = $_POST['name'];
                $protocol = match ($_POST['name']) {
                    'trojan' => "https://raw.githubusercontent.com/miaadp/v2ezOld/main/trojan_ws_tls.json",
                    default => "https://raw.githubusercontent.com/miaadp/v2ezOld/main/config.json"
                };
                $config = json_decode(file_get_contents('/etc/v2ray/config.json'), true);
                $path = $config['inbounds'][0]['streamSettings']['wsSettings']['path'];
                $port = $config['inbounds'][0]['port'];
                $new_config = json_decode(file_get_contents($protocol), true);
                $new_config['inbounds'][0]['streamSettings']['wsSettings']['path'] = $path;
                $new_config['inbounds'][0]['port'] = $port;
                $new_config = json_encode($new_config, 448);
                file_put_contents('/etc/v2ray/config.json', $new_config);
                shell_exec('sudo systemctl restart v2ray');
                show(true, 'done');
            }
            else {
                show(false, 'ERROR please set parameter name');
            }
            break;
        case 'get_log':
            shell_exec('sudo chmod -R 777 /var/log/v2ray');
            $handle = fopen('/var/log/v2ray/access.log', "r");
            $full_data = [];
            $emails = [];
            $i = [];
            while (($line = fgets($handle)) !== false){
                if (str_contains($line, 'email')) {
                    $line_data = explode(' ', $line);
                    $email = trim($line_data[7] ?? $line_data[6]);
                    if (!isset($i[$email])) {
                        $i[$email] = 0;
                    }
                    $ip = explode(':', $line_data[2]);
                    $ip = isset($ip[2]) ? $ip[1] : $ip[0];
                    if (!isset($full_data[$email])) {
                        $full_data[$email] = [];
                    }
                    if (isset($full_data[$email][$i[$email] - 1]) && $ip == $full_data[$email][$i[$email] - 1]['ip']) {
                        $full_data[$email][$i[$email] - 1]['date'] = $line_data[0] . ' ' . $line_data[1];
                    }
                    else {
                        $full_data[$email][$i[$email]] = [
                            'date' => $line_data[0] . ' ' . $line_data[1],
                            'ip'   => $ip,
                        ];
                        $i[$email]++;
                    }
                }
            }
            show(true, $full_data);
            shell_exec('> /var/log/v2ray/access.log');
            break;
        case 'access_log':
            shell_exec('sudo chmod -R 777 /var/log/v2ray');
            $handle = fopen('/var/log/v2ray/access.log', "r");
            $full_data = [];
            $i = [];
            $emails = [];
            while (($line = fgets($handle)) !== false){
                if (str_contains($line, 'email')) {
                    $line_data = explode(' ', $line);
                    $email = trim($line_data[7] ?? $line_data[6]);
                    if (!isset($i[$email])) {
                        $i[$email] = 0;
                    }
                    $ip = explode(':', $line_data[2]);
                    $ip = isset($ip[2]) ? $ip[1] : $ip[0];
                    if (!isset($full_data[$email])) {
                        $full_data[$email] = [];
                    }
                    if (isset($full_data[$email][$i[$email] - 1]) && $ip == $full_data[$email][$i[$email] - 1]['ip']) {
                        $full_data[$email][$i[$email] - 1]['date'] = $line_data[0] . ' ' . $line_data[1];
                    }
                    else {
                        $full_data[$email][$i[$email]] = [
                            'date' => $line_data[0] . ' ' . $line_data[1],
                            'ip'   => $ip,
                        ];
                        $i[$email]++;
                    }
                }
            }
            fclose($handle);
            foreach ($full_data as $email => $value) {
                $count = count($value);
                $email_connection = [];
                for ($i = 0; $i < $count; ++$i) {
                    $time = new DateTime($value[$i]['date'], new DateTimeZone('Asia/Shanghai'));
                    $plus_time = $time->modify('+30 second')->format("Y/m/d H:i:s");
                    $data = [];
                    for ($x = $i + 1; $x < $count; ++$x) {
                        if ($value[$x]['date'] < $plus_time) {
                            if (isset($data[$value[$x]['ip']])) {
                                $data[$value[$x]['ip']]++;
                            }
                            else {
                                $data[$value[$x]['ip']] = 1;
                            }
                        }
                        else {
                            break;
                        }
                    }
                    $data = array_diff($data, [1]);
                    $connection = count($data);
                    $email_connection[] = $connection;
                }
                //$email_connection = array_diff($email_connection, [0]);
                //if (empty($email_connection)) continue;
                $counts = array_count_values($email_connection);
                krsort($counts);
                $emails[$email] = $counts;
            }
            shell_exec('> /var/log/v2ray/access.log');
            show(true, $emails);
            break;
        case 'stats':
            if ($result = json_decode(shell_exec('v2ray api stats --server 127.0.0.1:10085 --json --reset user'), true)) {
                $result = $result['stat'];
                $data = [];
                foreach ($result as $value) {
                    preg_match('/user>>>([0-9a-f]*)>>>traffic>>>(down|up)link/', $value['name'], $res);
                    $uuid = $res[1];
                    $type = $res[2];
                    if ($type == 'down') {
                        $data[$uuid]['down'] = $value['value'] ?? 0;
                    }
                    else {
                        $data[$uuid]['up'] = $value['value'] ?? 0;
                    }
                    asort($data[$uuid]);
                }
                show(true, $data);
            }
            else {
                show(false, []);
            }
            break;
        case 'restart':
            shell_exec('sudo systemctl restart v2ray');
            show(true, 'done');
            break;
        default:
            show(false, 'type is wrong');
            break;
    }
}
else {
    show(false, 'who are you?');
}