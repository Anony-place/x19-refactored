import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { type MockBackendFixture, setupMockBackend, waitForAppReady } from './fixtures'
import { expect, test } from './test'

// #100406: in a Bot Mode group room a teammate's `@x19` handoff must give
// the primary profile (internal name `default`) its turn, exactly like
// `@x19 → @code-farmer` already does. The live roster stamps the primary
// row's handle as the bare profile id ("default"), and the mention parser let
// that stamped handle shadow the `@x19` alias — so the room settled with
// X19 never driven. The mock inference server scripts each member's line
// from the user's send (`E2E_SAY(<handle>)[…]`), so the assertion is on the
// persisted room log: an entry authored by `default` saying "B".

let fixture: MockBackendFixture | null = null

type Page = MockBackendFixture['page']

interface RoomLogEntry {
  from?: { kind?: string; name?: string }
  text?: string
}

async function openBots(page: Page): Promise<void> {
  const tab = page
    .getByRole('button', { name: 'Bots', exact: true })
    .or(page.getByRole('tab', { name: 'Bots', exact: true }))
    .first()

  await tab.click()
  await expect(page.getByRole('button', { name: 'New bot or group chat' })).toBeVisible()
}

async function createAgent(page: Page, name: string, title: string): Promise<void> {
  await page.getByRole('button', { name: 'New bot or group chat' }).click()
  await page.getByRole('menuitem', { name: 'New Bot' }).click()

  const dialog = page.getByRole('dialog', { name: 'New Bot' })
  await dialog.getByPlaceholder('inbox-triage').fill(name)
  await dialog.getByPlaceholder('Inbox Triage').fill(title)
  await dialog.getByRole('button', { name: 'Create Bot' }).click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })
  await expect(page.getByRole('button', { name: new RegExp(`^${title}\\b`) }).first()).toBeVisible({ timeout: 30_000 })
}

/** The plugin's persisted room log (`x19.plugin.x19-bots.group-chats`). */
async function roomLog(page: Page, group: string): Promise<RoomLogEntry[]> {
  return page.evaluate(name => {
    const raw = window.localStorage.getItem('x19.plugin.x19-bots.group-chats')
    const rooms = raw ? (JSON.parse(raw) as Record<string, { log?: RoomLogEntry[] }>) : {}

    return rooms[name]?.log ?? []
  }, group)
}

test.beforeAll(async () => {
  fixture = await setupMockBackend()
  await waitForAppReady(fixture, 120_000)
})

// Playwright requires an object-destructured fixture argument.
// eslint-disable-next-line no-empty-pattern
test.afterEach(async ({}, info) => {
  if (!fixture) {
    return
  }

  await info.attach('room-log', {
    body: JSON.stringify(await roomLog(fixture.page, 'X19, Code Farmer'), null, 2),
    contentType: 'application/json'
  })
  await info.attach('native-window', { body: await fixture.page.screenshot(), contentType: 'image/png' })
  await info.attach('runtime-source', {
    body: JSON.stringify(
      await fixture.app.evaluate(() => ({
        cwd: process.cwd(),
        argv: process.argv,
        root: process.env.X19_DESKTOP_X19_ROOT,
        home: process.env.X19_HOME
      })),
      null,
      2
    ),
    contentType: 'application/json'
  })
  await info.attach('desktop-log', {
    body: readFileSync(join(fixture.sandbox.x19Home, 'logs/desktop.log')),
    contentType: 'text/plain'
  })
})

test.afterAll(async () => {
  await fixture?.cleanup()
  fixture = null
})

test('a teammate handing off with @x19 drives the primary profile', async () => {
  test.setTimeout(420_000)
  const page = fixture!.page
  const group = 'X19, Code Farmer'

  await openBots(page)
  await createAgent(page, 'code-farmer', 'Code Farmer')

  await page.getByRole('button', { name: 'New bot or group chat' }).click()
  await page.getByRole('menuitem', { name: 'New Group Chat' }).click()

  const dialog = page.getByRole('dialog', { name: 'New Group Chat' })

  for (const title of ['X19', 'Code Farmer']) {
    await dialog.getByText(title, { exact: true }).locator('xpath=ancestor::label').getByRole('checkbox').click()
  }

  await dialog.getByRole('textbox', { name: 'Group name' }).fill(group)
  await dialog.getByRole('button', { name: 'Create Group (2)' }).click()

  const composer = page.getByRole('textbox', { name: `Message ${group}` }).filter({ visible: true })
  await expect(composer).toBeVisible({ timeout: 20_000 })

  // Only Code Farmer is addressed by the user. Its scripted reply hands off
  // to @x19; X19' scripted reply is "B". Neither script token carries
  // a literal `@`, so the user send itself never mentions X19.
  await composer.fill(
    '@code-farmer Please reply with one line only. ' +
      'E2E_SAY(code-farmer)[{at}x19 Please reply with the letter B.] E2E_SAY(x19)[B]'
  )
  await composer.press('Enter')

  // Code Farmer's handoff line lands first (the reverse direction is not in
  // question); then the room must NOT settle without X19' turn.
  await expect
    .poll(
      async () =>
        (await roomLog(page, group)).some(e => e.from?.name === 'code-farmer' && /@x19/.test(e.text || '')),
      {
        timeout: 180_000
      }
    )
    .toBe(true)

  await expect
    .poll(
      async () => (await roomLog(page, group)).some(e => e.from?.name === 'default' && (e.text || '').trim() === 'B'),
      {
        timeout: 180_000,
        message: 'the primary profile (default / @x19) never took its turn after being @mentioned by a teammate'
      }
    )
    .toBe(true)

  // And the transcript shows the handoff answered.
  await expect(page.getByText('B', { exact: true }).filter({ visible: true }).first()).toBeVisible()

  await composer.fill(
    '@x19 Begin the reverse handoff. E2E_SAY(x19)[{at}code-farmer Reply with D.] E2E_SAY(code-farmer)[D]'
  )
  await composer.press('Enter')
  await expect
    .poll(async () => (await roomLog(page, group)).some(e => e.from?.name === 'code-farmer' && e.text?.trim() === 'D'), {
      timeout: 180_000
    })
    .toBe(true)
})
