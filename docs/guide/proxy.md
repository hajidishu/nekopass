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

生产环境可用已有公共 CA 证书，或让 Nginx 终止 TLS。使用 Nginx 时，安装器选择 `proxy` 模式，在独立域名的 HTTPS `server` 中配置公共 CA 证书并启用 HTTP/2：

```nginx
location / {
    grpc_pass grpc://127.0.0.1:9443;
    grpc_read_timeout 3600s;
    grpc_send_timeout 3600s;
}
```

此处 `9443` 为安装器选择的节点后端监听端口。系统设置的节点连接方式选择 TLS，填写 Nginx 的对外域名与端口；节点地址为 `https://域名:端口`。已有节点连接地址需另行更新。

测试环境可选择 `plain`，系统设置的节点连接方式选择明文 HTTP/2，节点填写 `http://IP:9443`；这是独立 gRPC 端口，不是网页 `8080`。

```bash
sudo nginx -t
sudo systemctl reload nginx
```
