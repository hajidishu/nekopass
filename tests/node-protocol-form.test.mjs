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
