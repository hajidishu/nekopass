export async function copyText(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(value); return } catch { /* Try direct user-gesture copy below. */ }
  }
  const previous = document.activeElement as HTMLElement | null
  const field = document.createElement('textarea')
  field.value = value
  field.readOnly = true
  field.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0'
  document.body.appendChild(field)
  try {
    field.select()
    if (!document.execCommand('copy')) throw new Error('复制失败，请手动选择复制')
  } finally {
    field.remove()
    previous?.focus({preventScroll:true})
  }
}
