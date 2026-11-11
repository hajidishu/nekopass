export type DashboardPeriod='24h'|'7d'|'30d'
export type TrafficPoint={at:number;rx:number|null;tx:number|null}
export function dashboardDomain(period:DashboardPeriod,now:number){
 const step=period==='24h'?3600:86400
 const end=period==='24h'?Math.floor(now/step)*step:Math.floor((now+28800)/step)*step-28800
 return {start:end-(period==='24h'?24:period==='7d'?6:29)*step,end,step}
}
export function trafficPlot(points:TrafficPoint[],period:DashboardPeriod,now:number,width=800){
 const {start,end,step}=dashboardDomain(period,now),left=78,right=width-16,top=14,bottom=184
 const valid=(v:number|null)=>typeof v==='number'&&Number.isFinite(v)&&v>=0
 const visible=points.filter(p=>Number.isFinite(p.at)&&p.at>=start&&p.at<=end).sort((a,b)=>a.at-b.at)
 let peak=0;for(const p of visible)for(const v of [p.rx,p.tx])if(valid(v))peak=Math.max(peak,v!)
 const target=Math.max(1,peak*1.12),magnitude=10**Math.floor(Math.log10(target)),factor=target/magnitude
 const scale=(factor<=1?1:factor<=2?2:factor<=5?5:10)*magnitude
 const x=(at:number)=>left+(at-start)/Math.max(step,end-start)*(right-left),y=(v:number)=>bottom-Math.min(v,scale)/scale*(bottom-top)
 const curves=(['rx','tx'] as const).map(key=>{
  const segments:Array<Array<[number,number]>>=[];let segment:Array<[number,number]>=[],lastTime:number|null=null
  for(const p of visible){if(!valid(p[key])){if(segment.length)segments.push(segment);segment=[];lastTime=null;continue};if(lastTime!==null&&p.at-lastTime>step*1.5){if(segment.length)segments.push(segment);segment=[]};segment.push([x(p.at),y(p[key]!)]);lastTime=p.at}
  if(segment.length)segments.push(segment)
  const line=(s:Array<[number,number]>)=>s.map(([a,b],i)=>`${i?'L':'M'}${a.toFixed(2)},${b.toFixed(2)}`).join(' ')
  return {key,line:segments.map(line).join(' '),area:segments.filter(s=>s.length>1).map(s=>`${line(s)} L${s.at(-1)![0]},${bottom} L${s[0][0]},${bottom} Z`).join(' '),isolated:segments.filter(s=>s.length===1).map(s=>s[0]),last:(segments.at(-1)?.length||0)>1?segments.at(-1)?.at(-1):undefined}
 })
 const count=width<520?3:6
 const ticks=Array.from({length:count+1},(_,i)=>({at:start+(end-start)*i/count,x:left+(right-left)*i/count}))
 return {left,right,top,bottom,scale,curves,ticks,visible,x,y,hasData:curves.some(c=>c.line)}
}
export function dashboardSpark(values:ReadonlyArray<number|null>,percentage=false){
 const valid=(v:number|null)=>typeof v==='number'&&Number.isFinite(v)&&v>=0
 const numbers=values.filter(valid) as number[]
 if(!numbers.length)return {line:'',last:null as [number,number]|null}
 const min=percentage?0:Math.min(...numbers),max=percentage?100:Math.max(...numbers),span=max-min
 let line='',pen=false,last:[number,number]|null=null
 values.forEach((value,i)=>{if(!valid(value)){pen=false;return};const x=values.length===1?78:2+i/(values.length-1)*76,y=span?26-(Math.min(max,value!)-min)/span*22:15;line+=`${pen?' L':' M'}${x.toFixed(2)},${y.toFixed(2)}`;pen=true;last=[x,y]})
 return {line:line.trim(),last}
}
