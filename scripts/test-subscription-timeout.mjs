#!/usr/bin/env node
/**
 * 订阅拉取超时要管到读完响应体（issue #195）。
 *
 * 背景：原来 15 秒超时在拿到响应头后就清掉了。订阅服务器发完头、正文发一半停住时，
 * 这次拉取永远挂着；5 分钟一轮的源刷新有防重入锁，这一轮不结束，之后每轮都
 * 「上一轮源刷新检查尚未结束，跳过本次」——内置源、外部源、抓取模块的自动刷新全停。
 *
 * 不变量：
 *  - 正文中途停住：到点按「请求超时」失败，不挂住；
 *  - 正常订阅（正文慢慢发完、总时长在超时内）照常解析成功。
 *
 * 运行： node scripts/test-subscription-timeout.mjs   （或 npm test）
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const TMP = mkdtempSync(join(tmpdir(), 'iptv-sub-timeout-test-'))
process.env.mdataDir = TMP

const { fetchAndParseM3u } = await import('../utils/externalSources.js')

const HEAD = '#EXTM3U\n#EXTINF:-1 group-title="测试",甲台\nhttp://127.0.0.1/a.m3u8\n'
const TAIL = '#EXTINF:-1 group-title="测试",乙台\nhttp://127.0.0.1/b.m3u8\n'

const sockets = new Set()
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'audio/x-mpegurl' })
  if (req.url === '/stall.m3u') {
    res.write(HEAD) // 发了头和一部分正文就停住，不 end
    return
  }
  if (req.url === '/slow.m3u') {
    res.write(HEAD)
    setTimeout(() => res.end(TAIL), 300)
    return
  }
  res.end(HEAD + TAIL)
})
server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
await new Promise(r => server.listen(0, '127.0.0.1', r))
const BASE = `http://127.0.0.1:${server.address().port}`

let passed = 0
const check = async (name, fn) => { await fn(); passed++; console.log(`  ✅ ${name}`) }

/** 给被测调用再套一层硬上限：修复前它会永远 pending，测试不能跟着挂住 */
const within = (promise, ms) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error(`超过 ${ms}ms 仍未结束（拉取被挂住）`)), ms)),
])

try {
  console.log('订阅拉取超时（issue #195）')

  await check('正文中途停住：按超时失败，不挂住', async () => {
    const started = Date.now()
    await assert.rejects(
      within(fetchAndParseM3u(`${BASE}/stall.m3u`, { timeoutMs: 500 }), 5000),
      err => {
        assert.match(err.message, /请求超时/)
        return true
      },
    )
    assert.ok(Date.now() - started < 3000, '应在超时附近结束')
  })

  await check('正文慢慢发完（在超时内）：照常解析', async () => {
    const channels = await within(fetchAndParseM3u(`${BASE}/slow.m3u`, { timeoutMs: 2000 }), 5000)
    assert.equal(channels.length, 2)
  })

  await check('正常订阅：不受影响', async () => {
    const channels = await within(fetchAndParseM3u(`${BASE}/ok.m3u`), 5000)
    assert.deepEqual(channels.map(c => c.name), ['甲台', '乙台'])
  })

  console.log(`\n全部通过：${passed} 项`)
} finally {
  for (const s of sockets) s.destroy()
  server.close()
  rmSync(TMP, { recursive: true, force: true })
}
