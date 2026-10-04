import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, type Me } from './api'

export function usePage(load: (me: Me) => Promise<void>, options: { admin?: boolean; interval?: number } = {}) {
 const me = ref<Me | null>(null), loading = ref(true), error = ref(''), busy = ref(false)
 let timer: ReturnType<typeof setInterval> | undefined
 async function refresh() { if (!me.value) return; try { await load(me.value); error.value = '' } catch (e) { error.value = (e as Error).message } }
 async function run(task: () => Promise<void>) { busy.value = true; try { await task() } catch (e) { ElMessage.error((e as Error).message) } finally { busy.value = false } }
 onMounted(async () => { try { me.value = await api<Me>('me'); if (options.admin && !me.value.is_admin) { location.replace('/'); return }; await refresh() } catch (e) { error.value = (e as Error).message } finally { loading.value = false }; if (options.interval) timer = setInterval(() => { if (!document.hidden) void refresh() }, options.interval) })
 onUnmounted(() => { if (timer) clearInterval(timer) })
 return { me, loading, error, busy, refresh, run }
}

export function safeReturnPath(raw: string | null, isAdmin: boolean) {
 if (!raw || !raw.startsWith('/') || raw.startsWith('//') || /[\\\r\n]/.test(raw)) return '/'
 try { const u = new URL(raw, location.origin); if (u.origin !== location.origin || u.hash || u.username || u.password) return '/'; const path = u.pathname; const user = ['/', '/shop', '/orders', '/profile', '/forward_rules', '/node_status'].includes(path); const admin = ['/admin', '/admin/payment_gateways', '/admin/announcements', '/admin/users', '/admin/plans', '/admin/nodes', '/admin/node_groups', '/admin/settings'].includes(path) || /^\/admin\/users\/[1-9]\d*\/forward_rules$/.test(path) || /^\/admin\/nodes\/[1-9]\d*\/ddns$/.test(path); return user || isAdmin && admin ? path + u.search : '/' } catch { return '/' }
}
