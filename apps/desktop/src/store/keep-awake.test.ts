import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { storedBoolean } from '@/lib/storage'

import { $keepAwake, setKeepAwake } from './keep-awake'

const KEY = 'x19.desktop.keepAwake.v1'
const desktopWindow = window as unknown as { x19Desktop?: Window['x19Desktop'] }
const initialX19Desktop = desktopWindow.x19Desktop
const setKeepAwakeBridge = vi.fn()

beforeEach(() => {
  desktopWindow.x19Desktop = { setKeepAwake: setKeepAwakeBridge } as unknown as Window['x19Desktop']
  setKeepAwake(false)
  setKeepAwakeBridge.mockClear()
})

afterEach(() => {
  desktopWindow.x19Desktop = initialX19Desktop
})

describe('keep-awake store', () => {
  it('persists the pref and mirrors it to the main process', () => {
    setKeepAwake(true)
    expect($keepAwake.get()).toBe(true)
    expect(storedBoolean(KEY, false)).toBe(true)
    expect(setKeepAwakeBridge).toHaveBeenLastCalledWith(true)

    setKeepAwake(false)
    expect(storedBoolean(KEY, true)).toBe(false)
    expect(setKeepAwakeBridge).toHaveBeenLastCalledWith(false)
  })
})
