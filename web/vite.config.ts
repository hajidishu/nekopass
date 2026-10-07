import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

const documents = ['admin_orders','tickets','admin_tickets','register','referrals','shop','orders','admin_payment_gateways','home','login','profile','forward_rules','node_status','admin','admin_announcements','admin_users','admin_user_rules','admin_plans','admin_nodes','admin_node_ddns','admin_node_protocols','admin_node_groups','admin_settings']
export default defineConfig({
  appType: 'mpa',
  plugins: [vue()],
  build: { rollupOptions: { input: Object.fromEntries(documents.map(name => [name,fileURLToPath(new URL(`./pages/${name}.html`, import.meta.url))])) } },
})
