<script setup lang="ts">
defineProps<{ name: string }>()
const paths: Record<string, string> = {
 shop:'M4 7h16v14H4zM8 8V6a4 4 0 0 1 8 0v2', wallet:'M3 6h17v15H3zM3 6V3h14v3M15 11h7v5h-7z', orders:'M5 2h14v20l-3-2-4 2-4-2-3 2zM8 7h8M8 12h8M8 16h5',
 settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 1 0 0-8M12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2',
 home: 'm3 10 9-7 9 7M5 9v12h5v-7h4v7h5V9', user: 'M8 7a4 4 0 1 0 8 0 4 4 0 1 0-8 0M4 22v-3a8 8 0 0 1 16 0v3',
 rules: 'M8 6h13M8 12h13M8 18h13M3 6h.1M3 12h.1M3 18h.1', node: 'M3 4h18v13H3zM8 21h8M12 17v4',
 search: 'M10 3a7 7 0 1 0 0 14 7 7 0 1 0 0-14m5 12 6 6', refresh: 'M20 7a9 9 0 0 0-15-1L2 9m0-6v6h6M4 17a9 9 0 0 0 15 1l3-3m0 6v-6h-6',
 stats: 'M3 3v18h18M7 16v-5m5 5V6m5 10V9', add: 'M5 2h10l4 4v16H5zM14 2v5h5M8 14h8m-4-4v8',
 upload: 'M5 2h10l4 4v16H5zM9 13l3-3 3 3m-3-3v8', download: 'M5 2h10l4 4v16H5zM9 15l3 3 3-3m-3 3v-8',
 folder: 'M2 6h8l2 3h10v12H2zM11 15h6m-3-3v6', switch: 'M3 7h17m-4-4 4 4-4 4M21 17H4m4-4-4 4 4 4',
 clear: 'M12 2c0 7-7 8-7 14a7 7 0 0 0 14 0c0-5-4-7-7-14Z', delete: 'M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7',
 pause: 'M12 2a10 10 0 1 0 0 20 10 10 0 1 0 0-20M9 8v8m6-8v8', play: 'M12 2a10 10 0 1 0 0 20 10 10 0 1 0 0-20m-3 5 7 5-7 5Z',
 copy: 'M8 8h13v13H8zM16 8V3H3v13h5', edit: 'm4 16 12-12 4 4L8 20H4zm10-10 4 4M3 23h18',
 help: 'M12 2a10 10 0 1 0 0 20 10 10 0 1 0 0-20M9 8a3 3 0 0 1 6 0c0 3-3 2-3 6m0 3h.1',
 moon: 'M21 14A9 9 0 0 1 10 3 9 9 0 1 0 21 14Z', sun: 'M8 12a4 4 0 1 0 8 0 4 4 0 1 0-8 0M12 1v3m0 16v3M1 12h3m16 0h3M4 4l2 2m12 12 2 2M4 20l2-2M18 6l2-2',
 check: 'M4 12l5 5L20 6', menu: 'M3 6h18M3 12h18M3 18h18', close: 'm5 5 14 14M5 19 19 5', rename: 'M5 20 18 7l-4-4L1 16v4zm4-4 4 4M12 22h10',
}
</script>
<template><svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] || paths.rules" /></svg></template>
