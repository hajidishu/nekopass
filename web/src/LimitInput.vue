<script setup lang="ts">
import { computed } from 'vue'
const props = withDefaults(defineProps<{ modelValue: number; sentinel?: number; min?: number; max: number; precision?: number; unlimitedText?: string; unit?: string }>(), { sentinel: 0, min: 1, precision: 0, unlimitedText: '不限制', unit: '' })
const emit = defineEmits<{ 'update:modelValue': [value: number] }>()
const value = computed(() => props.modelValue === props.sentinel ? undefined : props.modelValue)
function update(value: number | null | undefined) { emit('update:modelValue', value ?? props.sentinel) }
</script>
<template><div class="limit-input" :class="{'has-unit':unit}"><el-input-number :model-value="value" :controls="false" :min="min" :max="max" :precision="precision" :value-on-clear="null" :placeholder="`留空则${unlimitedText}`" :inputmode="precision ? 'decimal' : 'numeric'" @update:model-value="update" /><span v-if="unit" class="limit-unit" aria-hidden="true">{{unit}}</span></div></template>
