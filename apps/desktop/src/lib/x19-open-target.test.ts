import { describe, expect, it } from 'vitest'

import {
  normalizeX19OpenString,
  pathFromX19DeepLink,
  pathFromOpenDeepLink,
  resolveX19OpenPath
} from './x19-open-target'

describe('normalizeX19OpenString', () => {
  it('accepts hash-router paths and strips a leading hash', () => {
    expect(normalizeX19OpenString('/index-network/intent/1')).toBe('/index-network/intent/1')
    expect(normalizeX19OpenString('#/index-network/intent/1')).toBe('/index-network/intent/1')
  })

  it('maps plugin-scoped x19:// deep links to the same path', () => {
    expect(normalizeX19OpenString('x19://index-network/intent/1')).toBe('/index-network/intent/1')
    expect(normalizeX19OpenString('x19://index-network/intent/1?focus=true')).toBe(
      '/index-network/intent/1?focus=true'
    )
  })

  it('maps x19://open/… deep links by stripping the open host', () => {
    expect(normalizeX19OpenString('x19://open/index-network/intent/1')).toBe('/index-network/intent/1')
    expect(normalizeX19OpenString('x19://open/settings/plugins')).toBe('/settings/plugins')
  })

  it('rejects reserved x19 kinds and unsafe paths', () => {
    expect(normalizeX19OpenString('x19://blueprint/morning-brief')).toBeNull()
    expect(normalizeX19OpenString('x19://plugin/install')).toBeNull()
    expect(normalizeX19OpenString('https://example.com/x')).toBeNull()
    expect(normalizeX19OpenString('/../etc/passwd')).toBeNull()
    expect(normalizeX19OpenString('index-network')).toBeNull()
  })
})

describe('resolveX19OpenPath', () => {
  it('merges structured path + params', () => {
    expect(resolveX19OpenPath({ path: '/index-network/intent/1', params: { focus: 'true' } })).toBe(
      '/index-network/intent/1?focus=true'
    )
  })

  it('resolves href the same as a bare string', () => {
    expect(resolveX19OpenPath({ href: 'x19://index-network/intent/1' })).toBe('/index-network/intent/1')
  })
})

describe('pathFromX19DeepLink', () => {
  it('builds the navigate path from a plugin-scoped deep-link payload', () => {
    expect(pathFromX19DeepLink('index-network', 'intent/1')).toBe('/index-network/intent/1')
  })

  it('builds the navigate path from x19://open/… payloads', () => {
    expect(pathFromOpenDeepLink('index-network/intent/1')).toBe('/index-network/intent/1')
    expect(pathFromX19DeepLink('open', 'agent/42')).toBe('/agent/42')
  })

  it('ignores reserved kinds', () => {
    expect(pathFromX19DeepLink('blueprint', 'morning-brief')).toBeNull()
    expect(pathFromX19DeepLink('plugin', 'install')).toBeNull()
    expect(pathFromX19DeepLink('skill', 'install')).toBeNull()
  })
})
