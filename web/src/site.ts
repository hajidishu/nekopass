import {reactive} from 'vue'
export const site=reactive({name:'Nekopass'})
export async function loadSite(){try{const response=await fetch('/api/v1/site');if(!response.ok)return;const data=await response.json();const old=site.name;site.name=data.site_name||'Nekopass';if(document.title.endsWith(' · '+old))document.title=document.title.slice(0,-old.length)+site.name;else if(document.title.endsWith(' · Nekopass'))document.title=document.title.replace(/Nekopass$/,site.name)}catch{/* keep local fallback */}}
