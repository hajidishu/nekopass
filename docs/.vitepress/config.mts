import { defineConfig } from 'vitepress'

const base = process.env.VITEPRESS_BASE || '/'
if (!base.startsWith('/') || !base.endsWith('/') || /[?#\\]/.test(base)) {
  throw new Error('VITEPRESS_BASE must be a path starting and ending with /')
}
const repository = process.env.GITHUB_REPOSITORY

export default defineConfig({
  lang: 'zh-CN',
  title: 'Nekopass',
  description: 'Nekopass 安装与使用文档',
  base,
  cleanUrls: false,
  appearance: 'dark',
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo-mark.svg` }]],
  markdown: { lineNumbers: false },
  themeConfig: {
    logo: '/logo-mark.svg',
    nav: [
      { text: '使用文档', link: '/guide/panel' },
      { text: '传输协议', link: '/protocols/' },
      ...(repository ? [{ text: '源码', link: `https://github.com/${repository}` }] : [])
    ],
    sidebar: [
      {
        text: '安装与接入',
        items: [
          { text: '安装面板', link: '/guide/panel' },
          { text: '安装节点', link: '/guide/node' }
        ]
      },
      {
        text: '传输协议',
        items: [
          { text: '协议选择', link: '/protocols/' },
          { text: 'TCP 直转', link: '/protocols/tcp' },
          { text: 'raw(tcp)', link: '/protocols/plain-tcp' },
          { text: 'h2', link: '/protocols/h2' },
          { text: 'TLS 安全设置', link: '/protocols/tls' }
        ]
      },
      {
        text: '用户功能',
        items: [
          { text: '注册与邀请', link: '/guide/account' },
          { text: '商城与余额', link: '/guide/shop' },
          { text: '转发规则', link: '/guide/rules' },
          { text: '工单', link: '/guide/tickets' },
          { text: '订单查询', link: '/guide/orders' },
          { text: '站点公告', link: '/guide/announcements' }
        ]
      },
      {
        text: '管理员与部署',
        items: [
          { text: '用户与套餐', link: '/guide/users' },
          { text: '节点与节点组 / DDNS', link: '/guide/nodes' },
          { text: '节点中转', link: '/guide/tunnel' },
          { text: '支付方式', link: '/guide/payments' },
          { text: '转发安全', link: '/guide/security' },
          { text: '日常管理', link: '/guide/manage' },
          { text: '反向代理', link: '/guide/proxy' },
          { text: '常见问题', link: '/guide/troubleshooting' }
        ]
      }
    ],
    search: {
      provider: 'local',
      options: {
        miniSearch: {
          options: {
            tokenize: (text) => Array.from(
              new Intl.Segmenter('zh-CN', { granularity: 'word' }).segment(text)
            ).filter(item => item.isWordLike).map(item => item.segment)
          }
        },
        translations: {
          button: { buttonText: '搜索', buttonAriaLabel: '搜索文档' },
          modal: {
            displayDetails: '显示摘要',
            resetButtonTitle: '清除搜索',
            backButtonTitle: '返回',
            noResultsText: '没有相关结果',
            footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' }
          }
        }
      }
    },
    outline: { level: [2, 3], label: '本页内容' },
    docFooter: { prev: '上一篇', next: '下一篇' },
    sidebarMenuLabel: '目录',
    returnToTopLabel: '返回顶部',
    skipToContentLabel: '跳到正文',
    notFound: { title: '页面不存在', quote: '', linkText: '返回首页', linkLabel: '返回首页' },
    darkModeSwitchLabel: '外观',
    lightModeSwitchTitle: '切换浅色',
    darkModeSwitchTitle: '切换深色'
  }
})
