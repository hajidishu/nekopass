# 文档站部署

GitHub 仓库 **Settings → Pages → Source** 选择 **GitHub Actions**。默认分支修改 `docs/` 后自动部署，也可手动运行 `Deploy documentation`。

工作流自动设置仓库子路径或自定义域名的根路径。只上传 `docs/.vitepress/dist/`。

本地预览（Node.js 22.12+）：

```bash
npm --prefix docs ci
npm --prefix docs run dev
```

构建：`npm --prefix docs run build`。构建结果预览：`npm --prefix docs run preview`。

手动构建仓库子路径时设置 `VITEPRESS_BASE=/仓库名/`；根域名使用 `/`。
