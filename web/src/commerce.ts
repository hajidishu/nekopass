export const cycles = [
 {key:'monthly',label:'月付'}, {key:'quarterly',label:'季付'}, {key:'semiannual',label:'半年付'},
 {key:'annual',label:'年付'}, {key:'biennial',label:'两年付'}, {key:'triennial',label:'三年付'}, {key:'onetime',label:'一次性'},
]
export function yuan(cents:number) { return (cents/100).toFixed(2) }
export function cycleName(key:string) { return cycles.find(c=>c.key===key)?.label||key }
export function dateText(value:string|null|undefined,empty='永不到期') {return value?new Date(value).toLocaleString():empty}
export function requestKey() { const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('') }
export type WalletEntry={id:number;order_id:number;amount_cents:number;balance_after_cents:number;kind:string;note:string;created_at:string}
export type PaymentMethod={id:number;name:string}
export type Checkout={url:string}
export function openCheckout(checkout:Checkout){const url=new URL(checkout.url);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error('支付地址无效');location.assign(url.href)}
export type Wallet={balance_cents:number;currency:string;entries:WalletEntry[];minimum_recharge_cents:number;payment_channels:PaymentMethod[]}
export type ShopPlan={purchase_limit:number;purchase_count:number;id:number;name:string;description:string;prices:Record<string,number>;speed_mbps:number;quota_bytes:number;max_rules:number;max_connections:number;ip_limit:number}
export type Quote={plan_id:number;plan_name:string;cycle:string;amount_cents:number;balance_cents:number;expires_at:string|null;next_reset_at:string|null;epoch:number;kind:string;replaces_plan:boolean}
