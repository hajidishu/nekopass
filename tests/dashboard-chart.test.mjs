import {test} from 'node:test'
import assert from 'node:assert/strict'
import {dashboardDomain,trafficPlot,dashboardSpark} from '../web/src/dashboard-chart.ts'

test('dashboard calendar uses UTC+8 and bounded requested ranges',()=>{
 const now=Date.parse('2026-11-10T01:00:00Z')/1000
 const days=dashboardDomain('7d',now)
 assert.equal(new Date(days.end*1000).toISOString(),'2026-11-09T16:00:00.000Z')
 assert.equal(days.end-days.start,6*86400)
 assert.equal(dashboardDomain('30d',now).end-dashboardDomain('30d',now).start,29*86400)
 const hours=dashboardDomain('24h',now);assert.equal(hours.end-hours.start,86400)
})
test('traffic distinguishes missing periods and measured idle zeroes',()=>{
 const now=Date.parse('2026-11-10T04:00:00Z')/1000
 const result=trafficPlot([{at:now-7200,rx:1,tx:2},{at:now-3600,rx:null,tx:0},{at:now,rx:3,tx:4}],'24h',now)
 assert.equal(result.curves[0].line.split('M').length-1,2)
 assert.equal(result.curves[1].line.split('M').length-1,1)
 assert.ok(result.curves[1].line.includes('184.00'),'measured zero must reach the baseline')
 assert.equal(result.hasData,true)
 assert.equal(trafficPlot([],'24h',now).hasData,false)
 const gap=trafficPlot([{at:now-7200,rx:1,tx:2},{at:now,rx:3,tx:4}],'24h',now)
 assert.equal(gap.curves[0].area,'','missing hour must not get an invented filled area')
 assert.equal(gap.curves[0].line.includes('NaN'),false)
})
test('mini charts retain missing samples and readable constant series',()=>{
 assert.equal(dashboardSpark([null,null]).line,'')
 assert.ok(dashboardSpark([0,0,0]).line.includes('15.00'))
 assert.equal(dashboardSpark([20,null,40],true).line.split('M').length-1,2)
 assert.equal(dashboardSpark([Infinity,-1,null]).last,null)
})
