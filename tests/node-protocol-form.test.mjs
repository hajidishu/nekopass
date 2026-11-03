import test from 'node:test'
import assert from 'node:assert/strict'
import {protocolDefaults,nodeTLSConfig,nodeSecurityInput,applyNodeSecurity,applyNodeTransport,nodeTransportInput} from '../web/src/node-protocol.ts'

test('old node configurations receive independent QUIC padding defaults',()=>{
 const a=nodeTLSConfig({server_name:'example.test'}),b=nodeTLSConfig(null)
 assert.equal(a.quic_padding.enabled,false)
 a.quic_padding.max_padding=320
 assert.notEqual(a.quic_padding.max_padding,b.quic_padding.max_padding)
})

test('security edits are isolated until saved and survive changing transport',()=>{
 const form=protocolDefaults()
 form.tunnel_transport='h3';form.tunnel_security='tls'
 const edit=nodeSecurityInput(form)
 edit.tls.quic_padding.enabled=true;edit.tls.quic_padding.max_padding=320
 assert.equal(form.tls.quic_padding.enabled,false)
 applyNodeSecurity(form,edit)
 assert.equal(form.tls.quic_padding.max_padding,320)
 const transport=nodeTransportInput(form);transport.tunnel_transport='raw_tcp'
 applyNodeTransport(form,transport)
 assert.equal(form.tls.quic_padding.enabled,true)
 assert.equal(form.tls.padding_enabled,false)
})

test('Mux transport edits are isolated and survive hidden transport/security choices',()=>{
 const form=protocolDefaults();const draft=nodeTransportInput(form)
 draft.mux.enabled=true;draft.mux.max_streams=48;draft.mux.max_connections=0
 assert.equal(form.mux.enabled,false)
 applyNodeTransport(form,draft)
 assert.equal(form.mux.enabled,true);assert.equal(form.mux.max_streams,48)
 draft.mux.max_streams=7;assert.equal(form.mux.max_streams,48)
 const next=nodeTransportInput(form);next.tunnel_transport='h3';applyNodeTransport(form,next)
 assert.equal(form.mux.enabled,true);assert.equal(form.tunnel_security,'tls')
 const security=nodeSecurityInput(form);applyNodeSecurity(form,security);assert.equal(form.mux.max_streams,48)
 const back=nodeTransportInput(form);back.tunnel_transport='raw_udp';applyNodeTransport(form,back);assert.equal(form.mux.max_connections,0)
})
