#!/usr/bin/env node
/**
 * 抓取模块可达性探测：逐个模块跑「取列表 → 换签 → 取清单 → 取分片」整条链路，每段记状态、
 * 耗时、主机。用来比较不同网络（大陆 / 海外）下哪些模块能用——本机跑一遍当基线，放到
 * GitHub Actions（美国 Azure）再跑一遍当海外视角。节目单另用 scripts/probe-epg.mjs。
 *
 * 用法:
 *   node scripts/probe-modules.mjs [--only id1,id2] [--samples 2] [--concurrency 4]
 *                                  [--json 明细.json] [--md 汇总.md]
 *
 * 每个模块默认取 2 个样本频道：第一个频道，加一个卫视（没有卫视就取另一个分组的第一个）。
 * 请求头按项目实际下发的给：浏览器 UA + 频道 #EXTVLCOPT 请求头 + 模块 upstreamHeaders，
 * 所以这里的失败基本就是网络层面的拒绝，而不是少带了防盗链头。
 *
 * 不碰真实数据目录：mdataDir 指向临时目录，远程配置拉取关闭。
 */
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.mdataDir = mkdtempSync(join(tmpdir(), 'iptv-probe-modules-'))
process.env.mbuiltInSourcesUrl = ''

const { listModules } = await import('../extractors/registry.js')
const { resolveConfig } = await import('../utils/extractorManager.js')
const { mapSettled } = await import('../utils/epgXmltv.js')

const args = process.argv.slice(2)
const argOf = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : '' }
const only = new Set(argOf('--only').split(',').map(s => s.trim()).filter(Boolean))
const sampleCount = Math.max(1, parseInt(argOf('--samples'), 10) || 2)
const concurrency = Math.max(1, parseInt(argOf('--concurrency'), 10) || 4)
const jsonOut = argOf('--json')
const mdOut = argOf('--md')

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
const FETCH_TIMEOUT_MS = 90 * 1000
const RESOLVE_TIMEOUT_MS = 60 * 1000
const HTTP_TIMEOUT_MS = 15 * 1000
const SEGMENT_PEEK_BYTES = 64 * 1024
// 这几个模块换签要起 Chromium；并发起会抢同一个 puppeteer profile，串行跑
const BROWSER_MODULES = new Set(['gdtv', 'hbtv', 'livechina'])
let browserChain = Promise.resolve()
function serialBrowser(fn) {
  const run = browserChain.then(fn, fn)
  browserChain = run.catch(() => {})
  return run
}

function withTimeout(promise, ms, label) {
  let timer
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label}超时 ${ms / 1000}s`)), ms) }),
  ]).finally(() => clearTimeout(timer))
}

function hostOf(url) {
  try { return new URL(url).host } catch { return '' }
}

function errText(error) {
  const cause = error?.cause
  const code = cause?.code || cause?.name || ''
  const msg = error?.name === 'AbortError' || error?.name === 'TimeoutError' ? '超时' : (error?.message || String(error))
  return code && !msg.includes(code) ? `${msg} (${code})` : msg
}

function optHeaders(opts) {
  const headers = {}
  for (const raw of opts || []) {
    const [key, ...rest] = String(raw).split('=')
    const value = rest.join('=')
    if (key === 'http-referrer') headers.Referer = value
    else if (key === 'http-user-agent') headers['User-Agent'] = value
    else if (key === 'http-origin') headers.Origin = value
  }
  return headers
}

function headersFor(url, base, upstreamHeaders) {
  const extra = typeof upstreamHeaders === 'function' ? (upstreamHeaders(url) || {}) : (upstreamHeaders || {})
  return { 'User-Agent': UA, ...base, ...extra }
}

/** 取一段 HTTP：只读前 limit 字节就断开（分片不必下完）。 */
async function peek(url, headers, limit) {
  const t0 = Date.now()
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS)
  try {
    const response = await fetch(url, { headers, redirect: 'follow', signal: ctrl.signal })
    const chunks = []
    let size = 0
    if (response.body) {
      const reader = response.body.getReader()
      while (size < limit) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
        size += value.length
      }
      reader.cancel().catch(() => {})
    }
    const body = Buffer.concat(chunks.map(c => Buffer.from(c)))
    return {
      status: response.status,
      finalUrl: response.url || url,
      host: hostOf(response.url || url),
      contentType: response.headers.get('content-type') || '',
      body,
      ms: Date.now() - t0,
    }
  } catch (error) {
    return { status: 0, error: errText(error), host: hostOf(url), ms: Date.now() - t0 }
  } finally {
    clearTimeout(timer)
  }
}

function firstVariant(text, base) {
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim().startsWith('#EXT-X-STREAM-INF')) continue
    for (let j = i + 1; j < lines.length; j++) {
      const t = lines[j].trim()
      if (!t || t.startsWith('#')) continue
      try { return new URL(t, base).href } catch { return null }
    }
  }
  return null
}

function lastSegment(text, base) {
  const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
  const last = lines[lines.length - 1]
  if (!last) return null
  try { return new URL(last, base).href } catch { return null }
}

function sniff(body) {
  if (!body?.length) return 'empty'
  if (body[0] === 0x47) return 'ts'
  const head = body.subarray(0, 12).toString('latin1')
  if (head.startsWith('FLV')) return 'flv'
  if (/ftyp|moof|styp|sidx/.test(head)) return 'fmp4'
  if (head.startsWith('ID3')) return 'id3'
  if (/^\s*</.test(head)) return 'html'
  if (/^\s*\{/.test(head)) return 'json'
  return 'bin'
}

function stageOk(stage) {
  return stage && stage.ok === true
}

async function probeStream(module, channel, config) {
  const sample = { name: channel.name, group: channel.group }
  const base = optHeaders(channel.opts)
  sample.route = channel.proxyHls ? 'proxy'
    : channel.relayHls ? 'relay'
      : (module.channelHlsMode || 'direct')
  let url = channel.url || ''
  let resolved = null

  if (!url && channel.deferredRef) {
    const t0 = Date.now()
    try {
      resolved = await withTimeout(module.resolve(channel.deferredRef, {
        account: { userId: '', token: '' },
        config,
        client: { key: 'probe-modules', tag: 'probe' },
        selfBase: '',
      }), RESOLVE_TIMEOUT_MS, '换签')
      url = resolved?.url || ''
      sample.resolve = url
        ? { ok: true, host: hostOf(url), ms: Date.now() - t0 }
        : { ok: false, error: resolved?.desc || '空地址', ms: Date.now() - t0 }
    } catch (error) {
      sample.resolve = { ok: false, error: errText(error), ms: Date.now() - t0 }
    }
    if (!url) return sample
  } else {
    sample.resolve = { ok: true, direct: true }
  }

  if (!/^https?:\/\//i.test(url)) {
    sample.manifest = { ok: false, skipped: true, error: `本机桥接地址 ${url.slice(0, 40)}` }
    return sample
  }

  const upstream = resolved?.upstreamHeaders
  const transform = typeof resolved?.upstreamUrlTransform === 'function' ? resolved.upstreamUrlTransform : (u => u)
  const streamType = resolved?.streamType || module.streamType || 'hls'
  sample.streamType = streamType

  if (streamType === 'flv') {
    const r = await peek(url, headersFor(url, base, upstream), SEGMENT_PEEK_BYTES)
    const kind = sniff(r.body)
    sample.manifest = { ok: true, direct: true, note: 'FLV 无清单' }
    sample.segment = { ok: r.status >= 200 && r.status < 300 && kind === 'flv', status: r.status, host: r.host, kind, bytes: r.body?.length || 0, ms: r.ms, error: r.error }
    return sample
  }

  let manifestText = ''
  let manifestBase = url
  if (resolved?.manifestText) {
    manifestText = resolved.manifestText
    manifestBase = resolved.manifestUrl || url
    sample.manifest = { ok: true, viaModule: true, host: hostOf(manifestBase) }
  } else {
    const r = await peek(url, headersFor(url, base, upstream), 2 * 1024 * 1024)
    manifestText = r.body?.toString('utf8') || ''
    manifestBase = r.finalUrl || url
    const isHls = manifestText.includes('#EXTM3U')
    sample.manifest = { ok: r.status >= 200 && r.status < 300 && isHls, status: r.status, host: r.host, ms: r.ms, error: r.error || (r.status && !isHls ? `不是 HLS（${sniff(r.body)}）` : undefined) }
    if (!sample.manifest.ok) return sample
  }

  const variant = firstVariant(manifestText, manifestBase)
  if (variant) {
    const target = transform(variant)
    const r = await peek(target, headersFor(target, base, upstream), 2 * 1024 * 1024)
    const text = r.body?.toString('utf8') || ''
    const isHls = text.includes('#EXTM3U')
    sample.variant = { ok: r.status >= 200 && r.status < 300 && isHls, status: r.status, host: r.host, ms: r.ms, error: r.error || (r.status && !isHls ? `不是 HLS（${sniff(r.body)}）` : undefined) }
    if (!sample.variant.ok) return sample
    manifestText = text
    manifestBase = r.finalUrl || target
  }

  const segment = lastSegment(manifestText, manifestBase)
  if (!segment) {
    sample.segment = { ok: false, error: '清单里没有分片' }
    return sample
  }
  const target = transform(segment)
  const r = await peek(target, headersFor(target, base, upstream), SEGMENT_PEEK_BYTES)
  const kind = sniff(r.body)
  sample.segment = {
    ok: r.status >= 200 && r.status < 300 && !['html', 'json', 'empty'].includes(kind),
    status: r.status, host: r.host, kind, bytes: r.body?.length || 0, ms: r.ms, error: r.error,
  }
  return sample
}

function pickSamples(channels) {
  const picked = []
  const add = c => { if (c && !picked.includes(c) && picked.length < sampleCount) picked.push(c) }
  add(channels[0])
  add(channels.find(c => /卫视/.test(c.name)))
  add(channels.find(c => c.group !== channels[0]?.group))
  for (const c of channels) add(c)
  return picked
}

async function probeModule(module) {
  const row = {
    id: module.id,
    name: module.name,
    category: module.category || 'standard',
    channelHlsMode: module.channelHlsMode || '',
    streamType: module.streamType || 'hls',
    samples: [],
  }
  const config = resolveConfig(module, {})
  const t0 = Date.now()
  let payload
  // 失败重试一次：单次超时多半是官网偶发慢，不该记成地域拦截
  for (let attempt = 1; attempt <= 2 && !payload; attempt++) {
    try {
      payload = await withTimeout(module.fetch(config, { timeoutMs: 10000 }), FETCH_TIMEOUT_MS, '取列表')
    } catch (error) {
      if (attempt === 2) {
        row.list = { ok: false, error: errText(error), attempts: attempt, ms: Date.now() - t0 }
        return row
      }
    }
  }
  const channels = []
  for (const group of payload?.groups || []) {
    for (const channel of group?.dataList || []) channels.push({ ...channel, group: group.name })
  }
  const skipped = payload?.meta?.skipped || []
  row.list = {
    ok: channels.length > 0,
    count: channels.length,
    groups: (payload?.groups || []).length,
    skipped: skipped.length,
    skippedSample: skipped.slice(0, 3).map(s => typeof s === 'string' ? s : (s?.reason || s?.name || JSON.stringify(s))),
    warnings: (payload?.meta?.warnings || []).slice(0, 3).map(String),
    ms: Date.now() - t0,
  }
  if (!channels.length) {
    row.list.error = '返回 0 个频道'
    return row
  }
  for (const channel of pickSamples(channels)) {
    try {
      row.samples.push(await probeStream(module, channel, config))
    } catch (error) {
      row.samples.push({ name: channel.name, group: channel.group, error: errText(error) })
    }
  }
  return row
}

function verdict(row) {
  if (!stageOk(row.list) && row.list?.count === 0 && row.list.warnings?.length) return '需配置'
  if (!stageOk(row.list)) return '列表不通'
  const okSamples = row.samples.filter(s => stageOk(s.segment))
  if (okSamples.length === row.samples.length && okSamples.length) return '通'
  if (okSamples.length) return '部分通'
  const first = row.samples[0] || {}
  if (!stageOk(first.resolve)) return '换签不通'
  if (first.manifest?.skipped) return '本机桥接'
  if (!stageOk(first.manifest) || (first.variant && !stageOk(first.variant))) return '清单不通'
  return '分片不通'
}

function cell(stage) {
  if (!stage) return '—'
  if (stage.direct && stage.ok) return '直链'
  if (stage.viaModule) return '✅ 模块内取'
  if (stage.ok) return `✅${stage.status ? ` ${stage.status}` : ''}${stage.kind ? ` ${stage.kind}` : ''}`
  if (stage.skipped) return `⏭ ${stage.error}`
  return `❌ ${stage.status || ''} ${stage.error || ''}`.replace(/\s+/g, ' ').trim()
}

async function vantage() {
  const out = {}
  const probes = [
    ['intl', 'https://ipinfo.io/json'],
    ['cn', 'https://myip.ipip.net/json'],
  ]
  await Promise.all(probes.map(async ([key, url]) => {
    try {
      const response = await fetch(url, { headers: { 'User-Agent': 'curl/8' }, signal: AbortSignal.timeout(8000) })
      out[key] = (await response.text()).slice(0, 400)
    } catch (error) {
      out[key] = `取不到：${errText(error)}`
    }
  }))
  return out
}

const modules = listModules().filter(m => !only.size || only.has(m.id))
const started = Date.now()
const where = await vantage()
console.log(`出口：${JSON.stringify(where)}`)
console.log(`探测 ${modules.length} 个模块，每个 ${sampleCount} 个样本，并发 ${concurrency}`)

const settled = await mapSettled(modules, concurrency, async module => {
  const row = BROWSER_MODULES.has(module.id) ? await serialBrowser(() => probeModule(module)) : await probeModule(module)
  row.verdict = verdict(row)
  console.log(`[${row.verdict}] ${module.id} ${module.name}：列表 ${cell(row.list)}${row.list?.count ? `（${row.list.count} 台）` : ''}`
    + row.samples.map(s => `\n    · ${s.name}：换签 ${cell(s.resolve)} | 清单 ${cell(s.manifest)}${s.variant ? ` → ${cell(s.variant)}` : ''} | 分片 ${cell(s.segment)}`).join(''))
  return row
})
const rows = settled.map((r, i) => r.status === 'fulfilled'
  ? r.value
  : { id: modules[i].id, name: modules[i].name, list: { ok: false, error: errText(r.reason) }, samples: [], verdict: '脚本出错' })

for (const module of modules) {
  try { await module.shutdown?.() } catch {}
}

const tally = {}
for (const row of rows) tally[row.verdict] = (tally[row.verdict] || 0) + 1

if (jsonOut) {
  writeFileSync(jsonOut, JSON.stringify({ at: new Date().toISOString(), vantage: where, sampleCount, tally, rows }, null, 2))
}

if (mdOut) {
  const lines = [
    '# 抓取模块可达性探测',
    '',
    `- 时间(UTC)：${new Date().toISOString()}，耗时 ${Math.round((Date.now() - started) / 1000)}s`,
    `- 出口：\`${JSON.stringify(where)}\``,
    `- 结果：${Object.entries(tally).map(([k, v]) => `${k} ${v}`).join('，')}`,
    '',
    '| 结论 | 模块 | 列表 | 样本 | 换签 | 清单 | 分片 | 线路 |',
    '| --- | --- | --- | --- | --- | --- | --- | --- |',
  ]
  for (const row of rows) {
    const listCell = row.list?.ok ? `✅ ${row.list.count} 台` : cell(row.list)
    if (!row.samples.length) {
      lines.push(`| ${row.verdict} | ${row.id} ${row.name} | ${listCell} | — | — | — | — | — |`)
      continue
    }
    row.samples.forEach((s, i) => {
      const manifest = s.variant ? `${cell(s.manifest)} → ${cell(s.variant)}` : cell(s.manifest)
      const hosts = [s.manifest?.host, s.segment?.host].filter(Boolean).filter((h, k, a) => a.indexOf(h) === k).join(' / ')
      lines.push(`| ${i ? '' : row.verdict} | ${i ? '' : `${row.id} ${row.name}`} | ${i ? '' : listCell} | ${s.name} | ${cell(s.resolve)} | ${manifest} | ${cell(s.segment)} | ${s.route}${hosts ? ` · ${hosts}` : ''} |`)
    })
  }
  writeFileSync(mdOut, `${lines.join('\n')}\n`)
}

console.log(`\n结果：${Object.entries(tally).map(([k, v]) => `${k} ${v}`).join('，')}，耗时 ${Math.round((Date.now() - started) / 1000)}s`)
process.exit(0)
