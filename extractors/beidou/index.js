/** 辽宁模块：云盛京官方沈阳三路，播放时生成短效 HLS 并全代理防盗链。 */
import { buildChannelGroups, claimsRef, clearCache, fetchChannelRows, resolveChannel, TENANTS } from './api.js'

const REGIONS = TENANTS.map(tenant => tenant.id)

export default {
  id: 'beidou',
  name: '辽宁',
  description: '云盛京官方沈阳新闻综合、经济、公共三路；只收录当前 live 频道，辽宁省台因官方入口故障暂时移除。',
  catalogVersion: 1,
  capabilities: { cache: 'disk', resolve: true, epg: false },
  outputGroupName: '辽宁',
  defaultRefreshMinutes: 10,
  refreshConfigurable: false,
  refreshDescription: '自动管理：每 10 分钟核对 live/replay 状态；播放时生成 30 分钟短签名，清单与分片经本机代理。',

  configSchema: [],

  async fetch(_config, ctx = {}) {
    const { rows, skipped, warnings } = await fetchChannelRows(REGIONS, {
      timeoutMs: ctx.timeoutMs,
      fetchImpl: ctx.fetchImpl,
      now: ctx.now,
    })
    const groups = buildChannelGroups(rows)
    const count = groups.reduce((sum, group) => sum + group.dataList.length, 0)
    if (!count) throw new Error('辽宁北斗融媒接口成功，但没有找到可用电视频道')
    return { groups, meta: { skipped, warnings } }
  },

  claimsRef,
  resolve: resolveChannel,
  clearResolveCache: clearCache,
}
