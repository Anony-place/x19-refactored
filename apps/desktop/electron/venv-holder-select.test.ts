import assert from 'node:assert/strict'

import { test } from 'vitest'

import { hasWindowsPathPrefix, isX19OwnedVenvDaemon } from './venv-holder-select'

const SCRIPTS = 'C:\\X19\\venv\\Scripts'

test('matches the hindsight daemon shim (exe under venv Scripts + hindsight cmdline)', () => {
  assert.equal(
    isX19OwnedVenvDaemon(
      'C:\\X19\\venv\\Scripts\\pythonw.exe',
      'C:\\X19\\venv\\Scripts\\pythonw.exe -m hindsight_api.main --daemon --idle-timeout 300 --port 9177',
      SCRIPTS
    ),
    true
  )
})

test('Windows path prefix match is ordinal case-insensitive', () => {
  assert.equal(
    isX19OwnedVenvDaemon(
      'c:\\x19\\venv\\scripts\\python.exe',
      'python.exe -m hindsight_api.main --daemon',
      'C:\\X19\\venv\\Scripts'
    ),
    true
  )
})

test('excludes external venv holders that are not the hindsight daemon', () => {
  // a user terminal running the x19 CLI from the venv — must NOT be killed
  assert.equal(isX19OwnedVenvDaemon('C:\\X19\\venv\\Scripts\\x19.exe', 'x19 chat -q "hi"', SCRIPTS), false)
  // an unrelated python script using the venv interpreter
  assert.equal(
    isX19OwnedVenvDaemon('C:\\X19\\venv\\Scripts\\python.exe', 'python C:\\tools\\import.py', SCRIPTS),
    false
  )
})

test('excludes exes outside the venv even when the cmdline mentions hindsight', () => {
  assert.equal(
    isX19OwnedVenvDaemon('C:\\Other\\pythonw.exe', 'pythonw -m hindsight_api.main --daemon', SCRIPTS),
    false
  )
})

test('prefix boundary: sibling dirs (ScriptsX) do not match', () => {
  assert.equal(hasWindowsPathPrefix('C:\\X19\\venv\\ScriptsX\\python.exe', SCRIPTS), false)
  assert.equal(hasWindowsPathPrefix('C:\\X19\\venv\\Scripts\\python.exe', SCRIPTS), true)
})

test('null/undefined fields never match', () => {
  assert.equal(isX19OwnedVenvDaemon(null, 'x', SCRIPTS), false)
  assert.equal(isX19OwnedVenvDaemon('C:\\X19\\venv\\Scripts\\pythonw.exe', null, SCRIPTS), false)
  assert.equal(isX19OwnedVenvDaemon(undefined, undefined, SCRIPTS), false)
})
