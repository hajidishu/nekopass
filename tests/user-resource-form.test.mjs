import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resourcesOf, resourceChanges, planResources } from '../web/src/user-resource-form.ts'

test('unchanged displays never overwrite live usage or round byte-exact quotas', () => {
  const user={quota_bytes:1234567890,traffic_bytes:17345,speed_mbps:500,node_group_ids:[2,1],expires_at:'2026-12-01T00:00:00Z'}
  const original=resourcesOf(user),form=resourcesOf(user)
  assert.deepEqual(resourceChanges(form,original),{})
  form.speed_mbps=20
  assert.deepEqual(resourceChanges(form,original),{speed_mbps:20})
  form.expires_at='2026-12-01T08:00:00+08:00';form.node_group_ids.reverse()
  assert.deepEqual(resourceChanges(form,original),{speed_mbps:20})
})

test('explicit traffic reset, unlimited limits, zero quota and permanent expiry stay distinct', () => {
  const original=resourcesOf({quota_bytes:100*1024**3,traffic_bytes:1024**3,speed_mbps:500,expires_at:'2026-12-01T00:00:00Z'})
  const form={...original,quota_gib:-1,traffic_gib:'',speed_mbps:0,expires_at:''}
  assert.deepEqual(resourceChanges(form,original),{speed_mbps:0,quota_bytes:-1,traffic_bytes:0,expires_at:''})
  form.quota_gib=0;form.traffic_gib='1.125'
  assert.equal(resourceChanges(form,original).quota_bytes,0)
  assert.equal(resourceChanges(form,original).traffic_bytes,1.125*1024**3)
  for(const value of ['-1','NaN','Infinity','1e3','1abc'])assert.throws(()=>resourceChanges({...form,traffic_gib:value},original))
})

test('plan selection initializes personal limits without sharing mutable arrays', () => {
  const plan={quota_bytes:-1,speed_mbps:10,max_rules:3,node_group_ids:[1,2],duration_days:0}
  const form={...planResources(plan),traffic_gib:'0'}
  form.node_group_ids.push(4)
  assert.deepEqual(plan.node_group_ids,[1,2])
  form.speed_mbps=0
  const body=resourceChanges(form)
  assert.equal(body.speed_mbps,0)
  assert.equal(body.quota_bytes,-1)
  assert.equal(body.expires_at,'')
  assert.equal(body.traffic_bytes,undefined)
})
