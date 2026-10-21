#!/usr/bin/env node
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { constants, createHash, createPublicKey, publicEncrypt } from 'node:crypto'
import { CLIENT_KEY_V3 } from '../extractors/beidou/client-auth-v3.js'
import { pruneUnclaimedCachedChannels } from '../utils/extractorManager.js'
import beidou from '../extractors/beidou/index.js'
import { createOauthSign, decodeOauth } from '../extractors/beidou/auth.js'
import {
  buildChannelGroups,
  normalizePrograms,
  playableStreamOf,
  signStreamUrl,
  clearCache,
  resolveChannel,
  TENANTS,
} from '../extractors/beidou/api.js'

let passed = 0
const check = (name, fn) => { fn(); passed++; console.log(`  ✅ ${name}`) }
const checkAsync = async (name, fn) => { clearCache(); await fn(); passed++; console.log(`  ✅ ${name}`) }
const authFixtures = JSON.parse(readFileSync(new URL('./fixtures/beidou-oauth.json', import.meta.url), 'utf8'))
const pullKey = 'MbLqEBSNY8Di3WFP'

console.log('辽宁北斗融媒模块测试')

check('模块只启用云盛京沈阳三路，不请求 405 的省台入口', () => {
  assert.deepEqual(beidou.configSchema, [])
  assert.equal(beidou.catalogVersion, 1)
  assert.deepEqual(TENANTS.map(tenant => [tenant.id, tenant.host, tenant.authVersion]), [['shenyang', 'mobile.yunshengjing.com', 3]])
})

check('只解析 type=22 的正式白名单频道', () => {
  const payload = { data: [
    { type: 22, config: JSON.stringify({ programs: [
      { id: 'd447fcc472f14c7f14872d4e26b12d8f', title: '沈阳新闻综合', cover: 'http://img/logo.jpg' },
      { id: 'ffffffffffffffffffffffffffffffff', title: '专题直播' },
      { id: 'c077b260424404846285cba1e1759280', title: '辽宁卫视' },
    ] }) },
    { type: 11, config: JSON.stringify({ programs: [{ id: '10d3de0d03c62e85a1a281bbde8b6952' }] }) },
  ] }
  assert.deepEqual(normalizePrograms(payload, 'shenyang'), [{
    id: 'd447fcc472f14c7f14872d4e26b12d8f', tenantId: 'shenyang', name: '沈阳新闻综合', logo: 'https://img/logo.jpg',
  }])
})

check('只接受 live 类型及对应租户 CDN 地址', () => {
  const good = { code: 200, data: { playableType: 'live', playableUrl: JSON.stringify({ m3u8: 'https://sygbdsttvzb.lnyun.com.cn/sygbdst/tvzb1.m3u8' }) } }
  const replay = { code: 200, data: { playableType: 'replay', programName: '说天下', playableUrl: 'https://sygbdsttvzb.lnyun.com.cn/sygbdst/tvzb1.m3u8?replay=1' } }
  const badHost = { code: 200, data: { playableType: 'live', playableUrl: JSON.stringify({ m3u8: 'https://evil.example/live.m3u8' }) } }
  assert.equal(playableStreamOf(good, 'shenyang').url, 'https://sygbdsttvzb.lnyun.com.cn/sygbdst/tvzb1.m3u8')
  assert.deepEqual(playableStreamOf(replay, 'shenyang'), { url: '', type: 'replay', programName: '说天下' })
  assert.equal(playableStreamOf(badHost, 'shenyang').url, '')
})

check('短签名格式、过期时间和摘要稳定', () => {
  const signed = new URL(signStreamUrl('https://sygbdsttvzb.lnyun.com.cn/sygbdst/tvzb1.m3u8', 'shenyang', pullKey, 1_700_000_000_000))
  assert.equal(signed.searchParams.get('auth_key'), '1700001800-0-0-f840433b7b81a88af50c80879315b8e6')
  assert.throws(() => signStreamUrl('https://evil.example/live.m3u8', 'shenyang', pullKey, 1_700_000_000_000), /不是该北斗融媒租户/)
})

check('省台旧行不再输出，沈阳三路保留辽宁分组和全代理', () => {
  const groups = buildChannelGroups([
    { id: 'c077b260424404846285cba1e1759280', tenantId: 'liaoning', name: '辽宁卫视', url: 'x', logo: '' },
    { id: 'd447fcc472f14c7f14872d4e26b12d8f', tenantId: 'shenyang', name: '沈阳新闻综合', url: 'y', logo: '' },
  ])
  assert.deepEqual(groups.map(group => group.name), ['辽宁'])
  assert.deepEqual(groups[0].dataList.map(channel => channel.name), ['沈阳新闻综合'])
  assert.ok(groups.every(group => group.dataList.every(channel => channel.proxyHls === true)))
})

check('模块认领范围不接受路径注入', () => {
  assert.equal(beidou.claimsRef('beidou-shenyang-d447fcc472f14c7f14872d4e26b12d8f'), true)
  assert.equal(beidou.claimsRef('beidou-liaoning-c077b260424404846285cba1e1759280'), false)
  assert.equal(beidou.claimsRef('beidou-shenyang-ffffffffffffffffffffffffffffffff'), false)
  assert.equal(beidou.claimsRef('beidou-fushun-b2326b3d482e30a9d95d63e09fc3f460'), false)
  assert.equal(beidou.claimsRef('beidou-liaoning-../../secret'), false)
})

check('鉴权签名与 Android 4.0.66 原生 liveSign 的实测结果一致', () => {
  const randomValues = [4, 1, 4, 6, 9]
  const sign = createOauthSign('918510749a0f319ec12ff695b1c95230', 1_788_441_716_000, () => randomValues.shift())
  assert.equal(sign, 'NDE0NjkxNzg4NDQxNzE2B5CC4623C1FB781E8B5F187535DFF25E')
})

check('解码两次官方响应，Referer 轮换而拉流密钥相同', () => {
  assert.deepEqual(decodeOauth(authFixtures.beforeRotation, 'bdrmtvzb.lnyun.com.cn'), {
    pullKey, referer: 'http://dggb.bdy.lnyun.com.cn', remainingSeconds: 120,
  })
  const payload = { code: 200, data: JSON.stringify(authFixtures.afterRotation.data) }
  assert.deepEqual(decodeOauth(payload, 'bdrmtvzb.lnyun.com.cn'), {
    pullKey, referer: 'http://iywv.bdy.lnyun.com.cn', remainingSeconds: 120,
  })
  assert.throws(() => decodeOauth(payload, 'sygbdsttvzb.lnyun.com.cn'), /CDN 不匹配/)
  for (const refer of ['', Buffer.alloc(128).toString('base64')]) {
    assert.throws(() => decodeOauth({ code: 200, data: { ...authFixtures.afterRotation.data, refer } }, 'bdrmtvzb.lnyun.com.cn'), /密文格式|解码失败/)
  }
  assert.throws(() => decodeOauth({ code: 200, data: { ...authFixtures.afterRotation.data, referTimeOut: '0' } }, 'bdrmtvzb.lnyun.com.cn'), /已过期/)
})

const v3PullKey = 'FixtureShenyangKey'
const v3PublicKey = createPublicKey(CLIENT_KEY_V3)
const encryptV3 = text => publicEncrypt({ key: v3PublicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(text)).toString('base64')
const v3Payload = refer => ({ code: 200, data: {
  domain: 'sygbdsttvzb.lnyun.com.cn', referTimeOut: '120',
  pullKey: encryptV3(v3PullKey), refer: encryptV3(refer),
} })
const v3Fixtures = {
  beforeRotation: v3Payload('fixture-before.bdy.lnyun.com.cn'),
  afterRotation: v3Payload('fixture-after.bdy.lnyun.com.cn'),
}

check('v3 配置可解码，错误版本、CDN、Referer 及过大密文均拒绝', () => {
  const payload = v3Fixtures.beforeRotation
  assert.equal(decodeOauth(payload, 'sygbdsttvzb.lnyun.com.cn', 3).pullKey, v3PullKey)
  assert.throws(() => decodeOauth(payload, 'sygbdsttvzb.lnyun.com.cn', 5), /解码失败/)
  assert.throws(() => decodeOauth(payload, 'sygbdsttvzb.lnyun.com.cn', 99), /不支持/)
  assert.throws(() => decodeOauth(payload, 'bdrmtvzb.lnyun.com.cn', 3), /CDN 不匹配/)
  assert.throws(() => decodeOauth(v3Payload('evil.example'), 'sygbdsttvzb.lnyun.com.cn', 3), /Referer 格式/)
  assert.throws(() => decodeOauth({ code: 200, data: { ...payload.data,
    pullKey: Buffer.alloc(128, 255).toString('base64'),
  } }, 'sygbdsttvzb.lnyun.com.cn', 3), /解码失败/)
})

check('升级时清理省台磁盘缓存，保留原沈阳频道引用', () => {
  const shenyang = { name: '沈阳新闻综合', deferredRef: 'beidou-shenyang-d447fcc472f14c7f14872d4e26b12d8f' }
  const pruned = pruneUnclaimedCachedChannels(beidou, [{ name: '辽宁', dataList: [
    { name: '辽宁卫视', deferredRef: 'beidou-liaoning-c077b260424404846285cba1e1759280' }, shenyang,
  ] }])
  assert.equal(pruned.removed, 1)
  assert.deepEqual(pruned.groups, [{ name: '辽宁', dataList: [shenyang] }])
})

await checkAsync('旧省台及未知沈阳引用立即拒绝，不触发任何上游请求', async () => {
  const fetchImpl = async () => assert.fail('已停用频道不应请求上游')
  for (const ref of ['beidou-liaoning-c077b260424404846285cba1e1759280', 'beidou-shenyang-ffffffffffffffffffffffffffffffff']) {
    const result = await resolveChannel(ref, { fetchImpl })
    assert.equal(result.url, '')
    assert.match(result.desc, /停用或引用无效/)
  }
})

const channelId = 'd447fcc472f14c7f14872d4e26b12d8f'
const anotherId = 'eaecc3f39a6e94f2ac6197c229b4cd6b'
const ref = `beidou-shenyang-${channelId}`
const t0 = 1_700_000_000_000

function mockApi() {
  const state = { oauthCalls: 0, payload: v3Fixtures.beforeRotation, fail: false }
  state.fetchImpl = async (raw, options) => {
    const url = new URL(raw)
    assert.equal(url.hostname, 'mobile.yunshengjing.com')
    let payload
    if (url.pathname.endsWith('/tab/page')) {
      assert.equal(url.searchParams.get('tabId'), '2')
      payload = { code: 200, data: [{ type: 22, config: { programs: [{ id: channelId }, { id: anotherId }] } }] }
    } else if (url.pathname.endsWith('/getPlayableUrl')) {
      payload = { code: 200, data: { playableType: 'live', playableUrl: JSON.stringify({ m3u8: 'https://sygbdsttvzb.lnyun.com.cn/sygbdst/tvzb1.m3u8' }) } }
    } else if (url.pathname.endsWith('/getOauth')) {
      state.oauthCalls++
      assert.equal(options.method, 'POST')
      assert.equal(options.headers.Referer, 'https://mobile.yunshengjing.com')
      assert.equal(url.searchParams.get('version'), '3')
      assert.ok([channelId, anotherId].includes(url.searchParams.get('domainId')))
      assert.ok(url.searchParams.get('sign'))
      if (state.fail) throw new Error('模拟鉴权服务不可用')
      payload = state.payload
    } else assert.fail(`未知接口 ${url}`)
    return { ok: true, json: async () => payload }
  }
  return state
}

await checkAsync('生产模块只抓沈阳目录，输出三路并无省台 405 告警', async () => {
  const api = mockApi()
  const originalFetch = api.fetchImpl
  api.fetchImpl = async (raw, options) => {
    const response = await originalFetch(raw, options)
    if (new URL(raw).pathname.endsWith('/tab/page')) return { ok: true, json: async () => ({ code: 200,
      data: [{ type: 22, config: { programs: [channelId, anotherId, 'acb1a5713531ac7feb7836b1b4db442c'].map(id => ({ id })) } }],
    }) }
    return response
  }
  const result = await beidou.fetch({}, { fetchImpl: api.fetchImpl, now: t0 })
  assert.deepEqual(result.meta.warnings, [])
  assert.deepEqual(result.groups[0].dataList.map(channel => channel.name), ['沈阳新闻综合', '沈阳经济', '沈阳公共'])
  assert.ok(result.groups[0].dataList.every(channel => beidou.claimsRef(channel.deferredRef) && channel.proxyHls))
})

await checkAsync('同一租户并发播放只取一次鉴权，提前刷新轮换 Referer', async () => {
  const api = mockApi()
  const ctx = { fetchImpl: api.fetchImpl, now: t0 }
  const results = await Promise.all([resolveChannel(ref, ctx), resolveChannel(`beidou-shenyang-${anotherId}`, ctx)])
  assert.equal(api.oauthCalls, 1)
  for (const result of results) {
    assert.ok(result.url)
    assert.equal(result.upstreamHeaders.Referer, 'http://fixture-before.bdy.lnyun.com.cn')
    const signed = new URL(result.url)
    const expires = 1700001800
    const digest = createHash('md5').update(`/sygbdst/tvzb1.m3u8-${expires}-0-0-${v3PullKey}`).digest('hex')
    assert.equal(signed.searchParams.get('auth_key'), `${expires}-0-0-${digest}`)
  }
  await resolveChannel(ref, { ...ctx, now: t0 + 89999 })
  assert.equal(api.oauthCalls, 1)
  api.payload = v3Fixtures.afterRotation
  const renewed = await resolveChannel(ref, { ...ctx, now: t0 + 90000 })
  assert.equal(api.oauthCalls, 2)
  assert.equal(renewed.upstreamHeaders.Referer, 'http://fixture-after.bdy.lnyun.com.cn')
})

await checkAsync('鉴权刷新失败不会发出过期播放地址，短暂退避后能恢复', async () => {
  const api = mockApi()
  const ctx = { fetchImpl: api.fetchImpl, now: t0 }
  await resolveChannel(ref, ctx)
  api.fail = true
  const failed = await resolveChannel(ref, { ...ctx, now: t0 + 90000 })
  assert.equal(failed.url, '')
  assert.match(failed.desc, /模拟鉴权服务不可用/)
  assert.equal(api.oauthCalls, 2)
  const retry = await resolveChannel(ref, { ...ctx, now: t0 + 91000 })
  assert.equal(retry.url, '')
  assert.equal(api.oauthCalls, 2)
  api.fail = false
  api.payload = v3Fixtures.afterRotation
  const recovered = await resolveChannel(ref, { ...ctx, now: t0 + 95000 })
  assert.ok(recovered.url)
  assert.equal(recovered.upstreamHeaders.Referer, 'http://fixture-after.bdy.lnyun.com.cn')
  assert.equal(api.oauthCalls, 3)
})

await checkAsync('即使官方剩余有效期很长，也至多缓存十分钟；清缓存会重取', async () => {
  const api = mockApi()
  api.payload = { code: 200, data: { ...v3Fixtures.beforeRotation.data, referTimeOut: '86400' } }
  const ctx = { fetchImpl: api.fetchImpl, now: t0 }
  await resolveChannel(ref, ctx)
  await resolveChannel(ref, { ...ctx, now: t0 + 600000 })
  assert.equal(api.oauthCalls, 2)
  clearCache()
  await resolveChannel(ref, { ...ctx, now: t0 + 600001 })
  assert.equal(api.oauthCalls, 3)
})

clearCache()
console.log(`\n${passed} 项测试全部通过`)
