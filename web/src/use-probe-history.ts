import {onBeforeUnmount,reactive,watch} from 'vue'
import {api,type ProbeHistoryPoint,type ProbeNode} from './api'
import {mergeProbeHistory,probeSample} from './probe-chart'

// Share all charts and duplicate node-group cards through one bounded cache.
export function useProbeHistory(source:()=>ProbeNode[]){
 const histories=reactive(new Map<number,ProbeHistoryPoint[]>())
 const errors=reactive(new Map<number,string>())
 const nextFetch=new Map<number,number>(),pending=new Set<number>(),inFlight=new Set<number>(),queue:number[]=[]
 let nodes=new Map<number,ProbeNode>(),active=0,disposed=false
 function pump(){
  while(!disposed&&active<4&&queue.length){
   const id=queue.shift()!
   if(!nodes.has(id)){pending.delete(id);continue}
   active++;inFlight.add(id)
   void api<ProbeHistoryPoint[]>(`node-status/${id}/history`).then(points=>{
    if(disposed||!nodes.has(id))return
    histories.set(id,mergeProbeHistory(points,histories.get(id)||[]));errors.delete(id);nextFetch.set(id,Date.now()+60000)
   }).catch((error:Error)=>{
    if(disposed||!nodes.has(id))return
    errors.set(id,error.message);nextFetch.set(id,Date.now()+30000)
   }).finally(()=>{active--;inFlight.delete(id);pending.delete(id);pump()})
  }
 }
 watch(source,current=>{
  nodes=new Map(current.map(node=>[node.id,node]))
  for(const id of histories.keys())if(!nodes.has(id)){histories.delete(id);errors.delete(id);nextFetch.delete(id)}
  for(let i=queue.length-1;i>=0;i--)if(!nodes.has(queue[i])){pending.delete(queue[i]);queue.splice(i,1)}
  for(const node of nodes.values()){
   const sample=probeSample(node),history=histories.get(node.id)||[]
   histories.set(node.id,sample?mergeProbeHistory(history,[sample]):history)
   if(Date.now()>=(nextFetch.get(node.id)||0)&&!pending.has(node.id)){pending.add(node.id);queue.push(node.id)}
  }
  pump()
 },{immediate:true})
 onBeforeUnmount(()=>{disposed=true;queue.length=0;histories.clear();errors.clear();nextFetch.clear();pending.clear();inFlight.clear();nodes.clear()})
 return {histories,errors}
}
