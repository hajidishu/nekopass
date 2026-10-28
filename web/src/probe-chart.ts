import type {ProbeHistoryPoint,ProbeNode} from './api'

export type ProbeSeriesKey=Exclude<keyof ProbeHistoryPoint,'at'>
export type ProbeSeries={key:ProbeSeriesKey;label:string;color:string}
export const probeHistoryLimit=120

export function mergeProbeHistory(...groups:ReadonlyArray<ReadonlyArray<ProbeHistoryPoint>>):ProbeHistoryPoint[]{
 const byTime=new Map<number,ProbeHistoryPoint>()
 for(const points of groups)for(const point of points)if(Number.isFinite(point.at))byTime.set(point.at,point)
 return [...byTime.values()].sort((a,b)=>a.at-b.at).slice(-probeHistoryLimit)
}

export function probeSample(node:ProbeNode):ProbeHistoryPoint|null{
 const p=node.metrics,at=Date.parse(node.updated_at||'')/1000
 if(!p||!Number.isFinite(at))return null
 const percent=(used?:number,total?:number)=>total?100*Number(used||0)/total:0
 return {at:Math.floor(at),cpu:p.cpu_ready?Number(p.cpu_percent||0):null,memory:p.memory_ready?percent(p.memory_used,p.memory_total):null,disk:p.disk_ready?percent(p.disk_used,p.disk_total):null,disk_read:p.disk_io_ready?Number(p.disk_read_bytes_per_second||0):null,disk_write:p.disk_io_ready?Number(p.disk_write_bytes_per_second||0):null}
}

export function probeScale(points:ReadonlyArray<ProbeHistoryPoint>,keys:ReadonlyArray<ProbeSeriesKey>,percentage:boolean):number{
 if(percentage)return 100
 let peak=0
 for(const point of points)for(const key of keys){const value=point[key];if(typeof value==='number'&&Number.isFinite(value)&&value>=0)peak=Math.max(peak,value)}
 if(!peak)return 1e6
 const target=peak*1.1,magnitude=10**Math.floor(Math.log10(target)),factor=target/magnitude
 return Math.max(1000,(factor<=1?1:factor<=2?2:factor<=5?5:10)*magnitude)
}

export function probePath(points:ReadonlyArray<ProbeHistoryPoint>,key:ProbeSeriesKey,scale:number,left:number){
 const last=points.at(-1)?.at||0,span=Math.max(60,Math.min(600,last-(points[0]?.at||last)+5)),start=last-span
 const gap=Math.max(30,(last-(points[0]?.at||last))/Math.max(1,points.length-1)*3)
 const segments:Array<Array<[number,number]>>=[]
 let segment:Array<[number,number]>=[],previous:number|null=null
 for(const point of points){
  if(point.at<start)continue
  const value=point[key]
  if(typeof value!=='number'||!Number.isFinite(value)||value<0){if(segment.length)segments.push(segment);segment=[];previous=null;continue}
  if(previous!==null&&point.at-previous>gap){if(segment.length)segments.push(segment);segment=[]}
  segment.push([left+(point.at-start)/span*(310-left),78-Math.min(scale,value)/scale*70]);previous=point.at
 }
 if(segment.length)segments.push(segment)
 const line=(s:Array<[number,number]>)=>s.map(([x,y],i)=>`${i?'L':'M'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
 return {span,line:segments.map(line).join(' '),area:segments.filter(s=>s.length>1).map(s=>`${line(s)} L${s.at(-1)![0].toFixed(2)},78 L${s[0][0].toFixed(2)},78 Z`).join(' '),last:segments.at(-1)?.at(-1)}
}
