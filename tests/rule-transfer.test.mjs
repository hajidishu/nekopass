import assert from 'node:assert/strict'
import { test } from 'node:test'
import { encodeNyanpassRules, nyanpassNeedsProxyTrust, parseRuleImport, prepareRuleImport } from '../web/src/rule-transfer.ts'

const destination = { userID: 7, nodeID: 11, egressNodeID: 12, groupID: 4, trustedCIDRs: [], randomPorts: false }
const example = { dest: ['192.0.2.10:25565'], listen_port: 9122, name: '示例', proxy_protocol: 3 }
const convert = text => prepareRuleImport(parseRuleImport(text), destination)

test('Nyanpass line format preserves destinations, ports, Unicode and sender v2', () => {
  const other = { ...example, dest: ['example.com:443', '[2001:db8::1]:443'], listen_port: 19132, name: '域名 IPv6' }
  const rows = convert('\uFEFF' + JSON.stringify(example) + '\r\n\r\n' + JSON.stringify(other) + '\r\n')
  assert.equal(rows.length, 2)
  assert.equal(rows[0].proxy_accept, 'off')
  assert.equal(rows[0].proxy_send, 'v2')
  assert.equal(rows[0].node_id, 11)
  assert.equal(rows[0].egress_node_id, 12)
  assert.equal(rows[0].user_id, 7)
  assert.equal(rows[0].group_id, 4)
  assert.equal(rows[0].listen_port, 9122)
  assert.deepEqual(rows[1].targets, other.dest)
  assert.equal(rows[1].name, other.name)
  assert.equal(encodeNyanpassRules(rows), JSON.stringify(example) + '\n' + JSON.stringify(other) + '\n')
})

test('single object, arrays and rules wrapper also accept compatible entries', () => {
  for (const text of [JSON.stringify(example), JSON.stringify([example]), JSON.stringify({ rules: [example] })]) assert.equal(convert(text)[0].proxy_send, 'v2')
})

test('independent Proxy Protocol receiving, v1 sending and v2 TCP/UDP mapping', () => {
  for (const [code, send] of [[undefined, 'off'], [0, 'off'], [1, 'v1'], [2, 'v2'], [3, 'v2']]) {
    const data = parseRuleImport(JSON.stringify({ ...example, proxy_protocol: code, accept_proxy_protocol: 1 }))
    assert.equal(nyanpassNeedsProxyTrust(data), true)
    assert.equal(prepareRuleImport(data, destination)[0].proxy_accept, 'auto')
    const [rule] = prepareRuleImport(data, { ...destination, trustedCIDRs: ['192.0.2.0/24'] })
    assert.equal(rule.proxy_accept, 'auto')
    assert.equal(rule.proxy_send, send)
    assert.deepEqual(rule.proxy_trusted_cidrs, [])
    const exported = JSON.parse(encodeNyanpassRules([rule]))
    assert.equal(exported.accept_proxy_protocol, 1)
    assert.equal(exported.proxy_protocol, send === 'off' ? undefined : send === 'v1' ? 1 : 3)
  }
  const closed = convert(JSON.stringify({ dest: example.dest, name: '全关闭', listen_port: 0 }))[0]
  assert.equal(closed.proxy_accept, 'off')
  assert.equal(closed.proxy_send, 'off')
  assert.deepEqual(JSON.parse(encodeNyanpassRules([closed])), { dest: example.dest, listen_port: 0, name: '全关闭' })
})

test('native backup preserves advanced options and pins owner to current managed account', () => {
  const native = { ...convert(JSON.stringify(example))[0], user_id: 99, proxy_accept: 'v2', proxy_trusted_cidrs: ['192.0.2.0/24'], enabled: false, balance: 'round_robin' }
  for (const value of [[native], { rules: [native] }]) {
    const data = parseRuleImport(JSON.stringify(value))
    assert.equal(data.format, 'nekopass')
    assert.deepEqual(prepareRuleImport(data, destination), [{ ...native, user_id: 7 }])
  }
})

test('optional random ports and direct forwarding use selected destination', () => {
  const data = parseRuleImport(JSON.stringify(example))
  const [rule] = prepareRuleImport(data, { ...destination, randomPorts: true, egressNodeID: 0 })
  assert.equal(rule.listen_port, 0)
  assert.equal(rule.egress_node_id, 0)
  assert.throws(() => prepareRuleImport(data, { ...destination, nodeID: 0 }), /入口节点/)
})

test('malformed data and unsupported fields fail before any submission', () => {
  assert.throws(() => parseRuleImport(JSON.stringify(example) + '\n{broken'), /第 2 行/)
  for (const patch of [{ dest: [] }, { dest: ['a', 5] }, { name: 2 }, { listen_port: '9122' }, { listen_port: -1 }, { listen_port: 65536 }, { listen_port: 1.5 }, { proxy_protocol: -1 }, { proxy_protocol: 4 }, { proxy_protocol: '3' }, { proxy_protocol: null }, { accept_proxy_protocol: 2 }, { accept_proxy_protocol: true }, { tls: {} }, { node_id: 99 }]) assert.throws(() => parseRuleImport(JSON.stringify({ ...example, ...patch })), /第 1 条/)
  for (const text of ['', 'null', '[]', '{}', '[1]', JSON.stringify([example, { targets: ['example.com:443'] }])]) assert.throws(() => parseRuleImport(text))
})

test('batch limit and UTF-8 size limit apply to pasted text as well as files', () => {
  assert.equal(convert(Array.from({ length: 500 }, () => JSON.stringify(example)).join('\n')).length, 500)
  assert.throws(() => convert(Array.from({ length: 501 }, () => JSON.stringify(example)).join('\n')), /1–500/)
  assert.throws(() => parseRuleImport('字'.repeat(350000)), /1 MiB/)
})
