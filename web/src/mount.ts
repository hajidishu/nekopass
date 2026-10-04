import { createApp, type Component } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './style.css'
import {loadSite} from './site'

export function applyTheme(dark: boolean) { document.documentElement.classList.toggle('dark', dark); localStorage.setItem('nekopass-theme-v3', dark ? 'dark' : 'light'); document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#101b2d' : '#eaf2fa') }
export function mount(component: Component, props: Record<string, unknown> = {}) {
 applyTheme(localStorage.getItem('nekopass-theme-v3') !== 'light')
 window.addEventListener('pageshow', e => { if (e.persisted) location.reload() })
 createApp(component, props).use(ElementPlus).mount('#app')
 void loadSite()
}
