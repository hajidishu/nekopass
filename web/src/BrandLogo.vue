<script setup lang="ts">
import logo from './assets/brand/logo.svg'
import mark from './assets/brand/logo-mark.svg'
withDefaults(defineProps<{ size?: 'small' | 'large' }>(), { size: 'small' })
</script>

<template>
 <img :src="size === 'large' ? logo : mark" alt="Nekopass" class="brand-logo" :class="`brand-logo--${size}`" width="640" height="640" />
</template>
