# 反向代理

## 网页 HTTPS

将以下配置放入已有的 Nginx HTTPS `server` 块：

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

后台「系统设置」的面板对外地址填写实际 HTTPS 地址。

代理在其他服务器时，在 `/etc/nekopass/control.env` 将 `NEKOPASS_TRUSTED_PROXIES` 设置为代理 IP / 网段，然后重启面板。

## 节点控制连接

默认一键安装已提供独立 TLS 控制入口，无需代理。需要由 Nginx 终止节点连接 TLS 时，安装器选择 `proxy` 模式，并在独立域名的 HTTPS `server` 中启用 HTTP/2：

```nginx
location / {
    grpc_pass grpc://127.0.0.1:9443;
    grpc_read_timeout 3600s;
    grpc_send_timeout 3600s;
}
```

此处 `9443` 为安装器选择的节点后端监听端口。系统设置填写 Nginx 的对外地址与端口；已有节点连接地址需另行更新。

```bash
sudo nginx -t
sudo systemctl reload nginx
```
