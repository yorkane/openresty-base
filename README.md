# openresty-base

定制 OpenResty Alpine Docker 镜像，在官方源码编译基础上额外集成：

- [lua-nginx-module](https://github.com/openresty/lua-nginx-module) — main 分支最新版本
- [nginx-dav-ext-module](https://github.com/mid1221213/nginx-dav-ext-module) — WebDAV PROPFIND/OPTIONS/LOCK/UNLOCK 支持
- [ngx-fancyindex](https://github.com/aperezdc/ngx-fancyindex) — 美化目录索引

## 镜像地址

| Registry | 地址 |
|----------|------|
| GitHub Container Registry | `ghcr.io/yorkane/openresty-base` |
| Docker Hub | `yorkane/openresty-base` |

## Tag 规则

| Tag | 说明 |
|-----|------|
| `latest` | 最新构建 |
| `RESTY_VERSION-YYYYMMDD` | OpenResty 版本 + 构建日期，如 `1.29.2.1-20260315` |

## 自动构建

GitHub Actions 每周一 UTC 00:00 自动触发构建，也可在 Actions 页面手动触发。

## 手动触发

在仓库 **Actions** → **Build and Publish** → **Run workflow** 按钮手动触发。

## 配置 Secrets

使用 Docker Hub 推送前，需在仓库 **Settings → Secrets and variables → Actions** 中添加：

| Secret 名称 | 说明 |
|-------------|------|
| `DOCKERHUB_USERNAME` | Docker Hub 用户名（`yorkane`） |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token |

GHCR 推送使用内置 `GITHUB_TOKEN`，无需额外配置。

## 本地构建

```bash
docker build -t openresty-base:local .
```
