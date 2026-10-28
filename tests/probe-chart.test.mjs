import test from 'node:test'
import assert from 'node:assert/strict'
import {mergeProbeHistory,probePath,probeSample,probeScale} from '../web/src/probe-chart.ts'
const point=(at,cpu=25,disk_read=2e6,disk_write=3e6)=>({at,cpu,memory:40,disk:60,disk_read,disk_write})

test('history is ordered, deduplicated and bounded across refreshes',()=>{
 const points=mergeProbeHistory(Array.from({length:180},(_,i)=>point(i)),[point(179,72)])
 assert.equal(points.length,120);assert.equal(points[0].at,60);assert.equal(points.at(-1).cpu,72)
 assert.equal(mergeProbeHistory([point(Infinity)]).length,0)
})
test('disk I/O preserves missing samples and measured zero values',()=>{
 const node={updated_at:'2026-10-29T00:00:00Z',metrics:{disk_io_ready:false,disk_read_bytes_per_second:100}}
 assert.equal(probeSample(node).disk_read,null)
 node.metrics.disk_io_ready=true;node.metrics.disk_read_bytes_per_second=0
 assert.equal(probeSample(node).disk_read,0)
 assert.equal(probeSample({...node,metrics:null}),null)
})
test('percentages use a fixed scale and both I/O lines share their peak',()=>{
 assert.equal(probeScale([point(1,2)],['cpu'],true),100)
 const points=[point(1,25,2e6,3e9)]
 const scale=probeScale(points,['disk_read','disk_write'],false)
 assert.ok(scale>=3e9);assert.ok(Number.isFinite(scale))
 assert.ok(probeScale([point(1,25,0,0)],['disk_read','disk_write'],false)>0)
 assert.equal(probePath([point(1,25,0,0)],'disk_read',1e6,76).last[1],78)
})
test('missing disk samples leave gaps rather than fabricated zeroes',()=>{
 const curve=probePath([point(0,25,1),point(5,25,null),point(10,25,2),point(15,25,3)],'disk_read',10,76)
 assert.equal((curve.line.match(/M/g)||[]).length,2)
 assert.equal((curve.line.match(/L/g)||[]).length,1)
 assert.equal((curve.area.match(/Z/g)||[]).length,1)
 assert.equal(curve.line.includes('NaN'),false)
})
