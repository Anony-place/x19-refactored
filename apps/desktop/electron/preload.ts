import { contextBridge, ipcRenderer, webFrame, webUtils } from 'electron'

import type { DesktopProfileRoute } from './desktop-profile'
import { customWindowControlsEnabled } from './window-controls'

// Which translucency the OS can back. Asked synchronously because the renderer
// needs it before its first paint, and answered by main because deciding it
// needs `os.release()` — a sandboxed preload may only require electron, events,
// timers and url, so importing node:os here throws before contextBridge runs
// and takes the ENTIRE bridge down with it (window.x19Desktop undefined =>
// "Desktop IPC bridge is unavailable"). No reply means no glass, which degrades
// to an ordinary opaque window rather than a page thinned over nothing.
const translucencySupport = ipcRenderer.sendSync('x19:translucency:support')
const hudWindowing = ipcRenderer.sendSync('x19:hud:windowing')
const hudNativeDrag = hudWindowing?.nativeDrag === true
const launchFlags = ipcRenderer.sendSync('x19:launch-flags')

contextBridge.exposeInMainWorld('x19Desktop', {
  glassSupported: translucencySupport?.glass === true,
  translucencySupported: translucencySupport?.translucency === true,
  // Launch-flag fact: the app was started with --local, so the renderer may
  // show the local-models surfaces. Static for the window's lifetime.
  localModelsEnabled: launchFlags?.localModels === true,
  // Launch-flag fact: the Nous free tier is on for this launch
  // (X19_GUEST_ONBOARDING=1 or --guest-onboarding). Read-only; the same
  // decision is stamped onto every backend the app spawns.
  guestOnboardingEnabled: launchFlags?.guestOnboarding === true,
  // Launch-flag fact: skip the first-run film (X19_SKIP_INTRO=1 or
  // --skip-intro). Rehearsal aid for the guided chat behind it.
  skipIntro: launchFlags?.skipIntro === true,
  getConnection: (profile, opts) => ipcRenderer.invoke('x19:connection', profile, opts),
  // Registry-scoped backend resolution: { connectionId, profile } → descriptor.
  getConnectionFor: payload => ipcRenderer.invoke('x19:connection:for', payload),
  getProfileRoutes: profiles => ipcRenderer.invoke('x19:plugin-profile-routes', profiles),
  revalidateConnection: () => ipcRenderer.invoke('x19:connection:revalidate'),
  touchBackend: (profile, options) => ipcRenderer.invoke('x19:backend:touch', profile, options),
  getPoolLimits: () => ipcRenderer.invoke('x19:pool-limits:get'),
  setPoolLimits: limits => ipcRenderer.invoke('x19:pool-limits:set', limits),
  getGatewayWsUrl: profile => ipcRenderer.invoke('x19:gateway:ws-url', profile),
  // Registry-scoped fresh WS URL: { connectionId, profile } → result shape of
  // getGatewayWsUrl, minted against that connection's backend.
  getGatewayWsUrlFor: payload => ipcRenderer.invoke('x19:gateway:ws-url-for', payload),
  // Union agent roster across every registered connection.
  getAgentRoster: () => ipcRenderer.invoke('x19:agents:roster'),
  openSessionWindow: (sessionId, opts) => ipcRenderer.invoke('x19:window:openSession', sessionId, opts),
  openSessionInTerminal: (sessionId, opts) => ipcRenderer.invoke('x19:window:openInTerminal', sessionId, opts),
  openWindow: (options?: DesktopProfileRoute) => ipcRenderer.invoke('x19:window:openInstance', options),
  openBrowserWindow: tabId => ipcRenderer.invoke('x19:window:openBrowser', tabId),
  onBrowserPopoutClosed: callback => {
    const listener = (_event, tabId) => callback(tabId)
    ipcRenderer.on('x19:browser-popout:closed', listener)

    return () => ipcRenderer.removeListener('x19:browser-popout:closed', listener)
  },
  claimAmbientCue: key => ipcRenderer.invoke('x19:ambient:claim', key),
  windowControls: {
    custom: customWindowControlsEnabled(),
    minimize: () => ipcRenderer.send('x19:window-control', 'minimize'),
    toggleMaximize: () => ipcRenderer.send('x19:window-control', 'toggle-maximize'),
    close: () => ipcRenderer.send('x19:window-control', 'close')
  },
  wakeIndicator: {
    getState: () => ipcRenderer.invoke('x19:wake-indicator:get'),
    setState: state => ipcRenderer.send('x19:wake-indicator:set', state),
    onState: callback => {
      const listener = (_event, state) => callback(state)
      ipcRenderer.on('x19:wake-indicator:state', listener)

      return () => ipcRenderer.removeListener('x19:wake-indicator:state', listener)
    }
  },
  chatOnboarding: {
    grow: request => ipcRenderer.send('x19:chat-onboarding:grow', request),
    soloBoot: () => ipcRenderer.send('x19:chat-onboarding:solo-boot')
  },
  introReveal: {
    open: (payload?: { hideMain?: boolean }) => ipcRenderer.invoke('x19:intro-reveal:open', payload),
    close: (payload?: { showMain?: boolean }) => ipcRenderer.invoke('x19:intro-reveal:close', payload),
    skip: () => ipcRenderer.send('x19:intro-reveal:skip'),
    ready: () => ipcRenderer.send('x19:intro-reveal:ready'),
    onSkip: callback => {
      const listener = () => callback()

      ipcRenderer.on('x19:intro-reveal:skip', listener)

      return () => ipcRenderer.removeListener('x19:intro-reveal:skip', listener)
    },
    onClosed: callback => {
      const listener = () => callback()

      ipcRenderer.on('x19:intro-reveal:closed', listener)

      return () => ipcRenderer.removeListener('x19:intro-reveal:closed', listener)
    }
  },
  petOverlay: {
    // Main renderer → main process: window lifecycle + drag. `request` is
    // `{ bounds, screen }`; resolves with the screen bounds it actually used.
    open: request => ipcRenderer.invoke('x19:pet-overlay:open', request),
    close: () => ipcRenderer.invoke('x19:pet-overlay:close'),
    setBounds: bounds => ipcRenderer.send('x19:pet-overlay:set-bounds', bounds),
    setIgnoreMouse: ignore => ipcRenderer.send('x19:pet-overlay:ignore-mouse', ignore),
    // Flip the overlay focusable (and focus it) while the composer needs keys.
    setFocusable: focusable => ipcRenderer.send('x19:pet-overlay:set-focusable', focusable),
    // Main renderer → overlay (forwarded by main): push the latest pet state.
    pushState: payload => ipcRenderer.send('x19:pet-overlay:state', payload),
    // Overlay → main renderer (forwarded by main): pop back in / composer submit.
    control: payload => ipcRenderer.send('x19:pet-overlay:control', payload),
    // Overlay subscribes to state pushes.
    onState: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:pet-overlay:state', listener)

      return () => ipcRenderer.removeListener('x19:pet-overlay:state', listener)
    },
    // Main renderer subscribes to overlay control messages.
    onControl: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:pet-overlay:control', listener)

      return () => ipcRenderer.removeListener('x19:pet-overlay:control', listener)
    }
  },
  // HUD mode: the chrome-free floating chat. A full app renderer (own gateway)
  // sized as a floating bar, so it mounts the real composer. Main owns the
  // window; `onChanged` keeps every window's toggle truthful.
  hud: {
    nativeDrag: hudNativeDrag,
    windowing: {
      clientPlacement: hudWindowing?.clientPlacement !== false,
      controlDrag: hudWindowing?.controlDrag === true,
      nativeDrag: hudNativeDrag,
      solid: hudWindowing?.solid === true,
      workspaceTransfer: hudWindowing?.workspaceTransfer === true
    },
    open: request => ipcRenderer.invoke('x19:hud:open', request),
    close: () => ipcRenderer.invoke('x19:hud:close'),
    setIgnoreMouse: ignore => ipcRenderer.send('x19:hud:ignore-mouse', ignore),
    beginMove: () => ipcRenderer.send('x19:hud:begin-move'),
    endMove: () => ipcRenderer.send('x19:hud:end-move'),
    moveBy: delta => ipcRenderer.send('x19:hud:move-by', delta),
    setWorkspaceTransfer: transferring => ipcRenderer.send('x19:hud:workspace-transfer', transferring),
    setBounds: bounds => ipcRenderer.send('x19:hud:set-bounds', bounds),
    resetLayout: () => ipcRenderer.invoke('x19:hud:reset-layout'),
    // Whether the band covers the window below the bar. Main pairs it with the
    // user's translucency setting to decide the native frost (macOS vibrancy /
    // Windows 11 DWM backdrop) — see hudFrostFor.
    setFrost: showing => ipcRenderer.invoke('x19:hud:frost', showing),
    // The HUD tells main which session it is on; main hands that back to the
    // app window when the HUD closes, so the app can re-home onto it.
    setSession: sessionId => ipcRenderer.send('x19:hud:session', sessionId),
    onGoto: callback => {
      const listener = (_event, sessionId) => callback(sessionId)
      ipcRenderer.on('x19:hud:goto', listener)

      return () => ipcRenderer.removeListener('x19:hud:goto', listener)
    },
    onChanged: callback => {
      const listener = (_event, state) => callback(state)
      ipcRenderer.on('x19:hud:changed', listener)

      return () => ipcRenderer.removeListener('x19:hud:changed', listener)
    },
    // Linux only, and silent elsewhere: where the cursor is, in page
    // coordinates, or null when it has left the window. Stands in for the
    // mousemove that `setIgnoreMouseEvents(true, { forward: true })` delivers on
    // macOS and Windows but not here.
    onCursor: callback => {
      const listener = (_event, point) => callback(point)
      ipcRenderer.on('x19:hud:cursor', listener)

      return () => ipcRenderer.removeListener('x19:hud:cursor', listener)
    },
    // Main's game-overlay watch: whether a fullscreen app (a game) is under
    // the HUD, so the renderer can step back to the low-opacity overlay
    // treatment while one owns the screen.
    onGameOverlay: callback => {
      const listener = (_event, state) => callback(state)
      ipcRenderer.on('x19:hud:game-overlay', listener)

      return () => ipcRenderer.removeListener('x19:hud:game-overlay', listener)
    }
  },
  // macOS native screenshot gesture; captures require a main-issued request.
  screenshot: process.platform === 'darwin' ? {
    getSettings: () => ipcRenderer.invoke('x19:screenshot:settings:get'),
    setEnabled: enabled => ipcRenderer.invoke('x19:screenshot:settings:set', enabled),
    openPermissionSettings: kind => ipcRenderer.invoke('x19:screenshot:permission', kind),
    capture: requestId => ipcRenderer.invoke('x19:screenshot:capture', requestId),
    onStatus: callback => {
      const listener = (_event, status) => callback(status)
      ipcRenderer.on('x19:screenshot:status', listener)

      return () => ipcRenderer.removeListener('x19:screenshot:status', listener)
    },
    onRequest: callback => {
      const channel = 'x19:screenshot:request'
      const listener = (_event, requestId) => callback(requestId)
      if (ipcRenderer.listenerCount(channel) === 0) {
        ipcRenderer.send('x19:screenshot:subscribe', true)
      }
      ipcRenderer.on(channel, listener)

      return () => {
        ipcRenderer.removeListener(channel, listener)
        if (ipcRenderer.listenerCount(channel) === 0) {
          ipcRenderer.send('x19:screenshot:subscribe', false)
        }
      }
    }
  } : undefined,
  // Quick Entry: the global-hotkey mini composer window. Main owns the OS
  // shortcut + the persisted preference; the quick window only captures text
  // and hands it back, and the primary renderer submits it through the normal
  // prompt path.
  quickEntry: {
    getSettings: () => ipcRenderer.invoke('x19:quick-entry:settings:get'),
    setSettings: patch => ipcRenderer.invoke('x19:quick-entry:settings:set', patch),
    submit: payload => ipcRenderer.send('x19:quick-entry:submit', payload),
    dismiss: () => ipcRenderer.send('x19:quick-entry:dismiss'),
    // Primary renderer → main → quick window: gateway connection state + the
    // recent-session options the target picker offers. Main caches the latest
    // payload so a freshly spawned quick window starts from truth.
    pushState: payload => ipcRenderer.send('x19:quick-entry:state', payload),
    // Quick window subscribes to those pushes.
    onState: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:quick-entry:state', listener)

      return () => ipcRenderer.removeListener('x19:quick-entry:state', listener)
    },
    // Main → primary renderer: a submit captured by the quick window.
    onSubmit: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:quick-entry:submit', listener)

      return () => ipcRenderer.removeListener('x19:quick-entry:submit', listener)
    },
    // Main → quick window: you were just summoned (reset draft + refocus).
    onShown: callback => {
      const listener = () => callback()
      ipcRenderer.on('x19:quick-entry:shown', listener)

      return () => ipcRenderer.removeListener('x19:quick-entry:shown', listener)
    }
  },
  getBootProgress: () => ipcRenderer.invoke('x19:boot-progress:get'),
  getConnectionConfig: profile => ipcRenderer.invoke('x19:connection-config:get', profile),
  saveConnectionConfig: payload => ipcRenderer.invoke('x19:connection-config:save', payload),
  applyConnectionConfig: payload => ipcRenderer.invoke('x19:connection-config:apply', payload),
  testConnectionConfig: payload => ipcRenderer.invoke('x19:connection-config:test', payload),
  // Opt-in OS-keychain encryption for stored gateway secrets (default off —
  // see secret-storage-policy.ts). get never touches the OS keychain.
  getSecretStorageEncryption: () => ipcRenderer.invoke('x19:secret-storage:get'),
  setSecretStorageEncryption: (on: boolean) => ipcRenderer.invoke('x19:secret-storage:set', on),
  // v2 multi-connection registry: named agent sources (local / remote / cloud / ssh).
  connections: {
    list: () => ipcRenderer.invoke('x19:connections:list'),
    save: payload => ipcRenderer.invoke('x19:connections:save', payload),
    remove: id => ipcRenderer.invoke('x19:connections:remove', id),
    setPrimary: id => ipcRenderer.invoke('x19:connections:set-primary', id),
    setLaunchMode: mode => ipcRenderer.invoke('x19:connections:set-launch-mode', mode),
    setLastUsed: id => ipcRenderer.invoke('x19:connections:set-last-used', id),
    test: id => ipcRenderer.invoke('x19:connections:test', id),
    updateManaged: id => ipcRenderer.invoke('x19:connections:update-managed', id),
    // Fan out `x19 update` to every eligible registered connection.
    // Optional excludeIds skips rows the caller updates through another path.
    updateAll: options => ipcRenderer.invoke('x19:connections:update-all', options),
    // Registry lifecycle push (main → renderer): a connection was removed or
    // materially edited, so secondaries scoped to it must be disposed (and,
    // for edits, re-dialed at the new target).
    onChanged: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:connections:changed', listener)

      return () => ipcRenderer.removeListener('x19:connections:changed', listener)
    }
  },
  sshConfigHosts: () => ipcRenderer.invoke('x19:ssh-config:hosts'),
  sshResolveHost: host => ipcRenderer.invoke('x19:ssh-config:resolve', host),
  probeConnectionConfig: remoteUrl => ipcRenderer.invoke('x19:connection-config:probe', remoteUrl),
  oauthLoginConnectionConfig: remoteUrl => ipcRenderer.invoke('x19:connection-config:oauth-login', remoteUrl),
  oauthLogoutConnectionConfig: remoteUrl => ipcRenderer.invoke('x19:connection-config:oauth-logout', remoteUrl),
  // X19 Cloud: one portal login powers discovery + silent per-agent sign-in
  // (cloud-auto-discovery Phase 3).
  cloud: {
    status: () => ipcRenderer.invoke('x19:cloud:status'),
    login: () => ipcRenderer.invoke('x19:cloud:login'),
    logout: () => ipcRenderer.invoke('x19:cloud:logout'),
    discover: org => ipcRenderer.invoke('x19:cloud:discover', org),
    agentSignIn: dashboardUrl => ipcRenderer.invoke('x19:cloud:agent-sign-in', dashboardUrl)
  },
  profile: {
    getDefault: () => ipcRenderer.invoke('x19:profile:default:get'),
    setDefault: (route: DesktopProfileRoute) => ipcRenderer.invoke('x19:profile:default:set', route),
    onDefaultChanged: (callback: (route: DesktopProfileRoute | null) => void) => {
      const listener = (_event: Electron.IpcRendererEvent, route: DesktopProfileRoute | null) => callback(route)
      ipcRenderer.on('x19:profile:default:changed', listener)

      return () => ipcRenderer.removeListener('x19:profile:default:changed', listener)
    },
    get: () => ipcRenderer.invoke('x19:profile:get'),
    remember: name => ipcRenderer.invoke('x19:profile:remember', name),
    set: name => ipcRenderer.invoke('x19:profile:set', name)
  },
  api: request => ipcRenderer.invoke('x19:api', request),
  notify: payload => ipcRenderer.invoke('x19:notify', payload),
  requestMicrophoneAccess: () => ipcRenderer.invoke('x19:requestMicrophoneAccess'),
  readWindowBelow: () => ipcRenderer.invoke('x19:window:readBelow'),
  readFileDataUrl: filePath => ipcRenderer.invoke('x19:readFileDataUrl', filePath),
  readFileDataUrlForAttach: filePath => ipcRenderer.invoke('x19:readFileDataUrlForAttach', filePath),
  dataUrlReadMax: {
    get: () => ipcRenderer.invoke('x19:data-url-read-max:get'),
    set: maxMb => ipcRenderer.invoke('x19:data-url-read-max:set', maxMb)
  },
  readFileText: filePath => ipcRenderer.invoke('x19:readFileText', filePath),
  readPluginSource: (filePath: string) => ipcRenderer.invoke('x19:readPluginSource', filePath),
  selectPaths: options => ipcRenderer.invoke('x19:selectPaths', options),
  selectSavePath: options => ipcRenderer.invoke('x19:selectSavePath', options),
  writeClipboard: text => ipcRenderer.invoke('x19:writeClipboard', text),
  readClipboard: () => ipcRenderer.invoke('x19:readClipboard'),
  saveGatewayFile: payload => ipcRenderer.invoke('x19:saveGatewayFile', payload),
  saveImageFromUrl: url => ipcRenderer.invoke('x19:saveImageFromUrl', url),
  contextMenuEdit: command => ipcRenderer.invoke('x19:context-menu:edit', command),
  contextMenuCopyImage: () => ipcRenderer.invoke('x19:context-menu:copy-image'),
  contextMenuSpellcheck: action => ipcRenderer.invoke('x19:context-menu:spellcheck', action),
  contextMenuGuestAddWord: payload => ipcRenderer.invoke('x19:context-menu:guest-add-word', payload),
  onContextMenuSpellcheck: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:context-menu-spellcheck', listener)

    return () => ipcRenderer.removeListener('x19:context-menu-spellcheck', listener)
  },
  saveImageBuffer: (data, ext, name) => ipcRenderer.invoke('x19:saveImageBuffer', { data, ext, name }),
  capturePreview: payload => ipcRenderer.invoke('x19:capturePreview', payload),
  savePastedText: text => ipcRenderer.invoke('x19:savePastedText', { text }),
  saveClipboardImage: () => ipcRenderer.invoke('x19:saveClipboardImage'),
  getPathForFile: file => {
    try {
      return webUtils.getPathForFile(file) || ''
    } catch {
      return ''
    }
  },
  normalizePreviewTarget: (target, baseDir) => ipcRenderer.invoke('x19:normalizePreviewTarget', target, baseDir),
  watchPreviewFile: url => ipcRenderer.invoke('x19:watchPreviewFile', url),
  watchDirectory: dir => ipcRenderer.invoke('x19:watchDirectory', dir),
  stopPreviewFileWatch: id => ipcRenderer.invoke('x19:stopPreviewFileWatch', id),
  setActiveWork: payload => ipcRenderer.send('x19:active-work', payload),
  setTitleBarTheme: payload => ipcRenderer.send('x19:titlebar-theme', payload),
  setNativeTheme: mode => ipcRenderer.send('x19:native-theme', mode),
  setTranslucency: payload => ipcRenderer.send('x19:translucency', payload),
  setKeepAwake: on => ipcRenderer.send('x19:keep-awake', on),
  setDisableF12: blocked => ipcRenderer.send('x19:devtools:disable-f12', blocked),
  setPreviewShortcutActive: active => ipcRenderer.send('x19:previewShortcutActive', Boolean(active)),
  openExternal: url => ipcRenderer.invoke('x19:openExternal', url),
  mcpOauth: {
    // One-shot loopback listener for MCP OAuth against remote backends: bind
    // on this machine, hand redirectUri to mcp.servers.oauth.start, then wait
    // for the provider redirect and relay code/state via oauth.callback.
    listen: () => ipcRenderer.invoke('x19:mcp-oauth:listen'),
    wait: (id, timeoutMs) => ipcRenderer.invoke('x19:mcp-oauth:wait', id, timeoutMs),
    cancel: id => ipcRenderer.invoke('x19:mcp-oauth:cancel', id)
  },
  openPreviewInBrowser: url => ipcRenderer.invoke('x19:openPreviewInBrowser', url),
  reachPreviewUrl: url => ipcRenderer.invoke('x19:preview:reach', url),
  setActiveConnectionRoute: route => ipcRenderer.send('x19:connection:active-route', route),
  fetchLinkTitle: url => ipcRenderer.invoke('x19:fetchLinkTitle', url),
  resolveFavicon: url => ipcRenderer.invoke('x19:resolveFavicon', url),
  sanitizeWorkspaceCwd: cwd => ipcRenderer.invoke('x19:workspace:sanitize', cwd),
  settings: {
    getDefaultProjectDir: () => ipcRenderer.invoke('x19:setting:defaultProjectDir:get'),
    setDefaultProjectDir: dir => ipcRenderer.invoke('x19:setting:defaultProjectDir:set', dir),
    pickDefaultProjectDir: () => ipcRenderer.invoke('x19:setting:defaultProjectDir:pick')
  },
  zoom: {
    // Current zoom of this window, as { level, percent }.
    get: () => ipcRenderer.invoke('x19:zoom:get'),
    // Synchronous zoom factor (1 = 100%). Coordinate math needs it in the
    // same tick as the event it converts, so no IPC round-trip here.
    factor: () => webFrame.getZoomFactor(),
    setPercent: percent => ipcRenderer.send('x19:zoom:set-percent', percent),
    // Fires on every zoom change, including the Ctrl/Cmd +/-/0 shortcuts,
    // so the settings UI can stay in sync with the keyboard.
    onChanged: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:zoom:changed', listener)

      return () => ipcRenderer.removeListener('x19:zoom:changed', listener)
    }
  },
  revealLogs: () => ipcRenderer.invoke('x19:logs:reveal'),
  getRecentLogs: () => ipcRenderer.invoke('x19:logs:recent'),
  // Fire-and-forget: persists a renderer error-boundary catch (with component
  // stack) to desktop.log so crashes survive the window (#79428).
  reportRendererError: report => ipcRenderer.send('x19:logs:renderer-error', report),
  readDir: dirPath => ipcRenderer.invoke('x19:fs:readDir', dirPath),
  gitRoot: startPath => ipcRenderer.invoke('x19:fs:gitRoot', startPath),
  revealPath: targetPath => ipcRenderer.invoke('x19:fs:reveal', targetPath),
  openDir: dirPath => ipcRenderer.invoke('x19:fs:openDir', dirPath),
  desktopPluginsRoot: () => ipcRenderer.invoke('x19:fs:desktopPluginsRoot'),
  reconcileDesktopPlugins: () => ipcRenderer.invoke('x19:fs:reconcileDesktopPlugins'),
  logsRoot: () => ipcRenderer.invoke('x19:fs:logsRoot'),
  renamePath: (targetPath, newName) => ipcRenderer.invoke('x19:fs:rename', targetPath, newName),
  writeTextFile: (filePath, content) => ipcRenderer.invoke('x19:fs:writeText', filePath, content),
  trashPath: targetPath => ipcRenderer.invoke('x19:fs:trash', targetPath),
  git: {
    worktreeList: repoPath => ipcRenderer.invoke('x19:git:worktreeList', repoPath),
    worktreeAdd: (repoPath, options) => ipcRenderer.invoke('x19:git:worktreeAdd', repoPath, options),
    worktreeRemove: (repoPath, worktreePath, options) =>
      ipcRenderer.invoke('x19:git:worktreeRemove', repoPath, worktreePath, options),
    branchSwitch: (repoPath, branch) => ipcRenderer.invoke('x19:git:branchSwitch', repoPath, branch),
    branchList: repoPath => ipcRenderer.invoke('x19:git:branchList', repoPath),
    baseBranchList: repoPath => ipcRenderer.invoke('x19:git:baseBranchList', repoPath),
    repoStatus: repoPath => ipcRenderer.invoke('x19:git:repoStatus', repoPath),
    fileDiff: (repoPath, filePath) => ipcRenderer.invoke('x19:git:fileDiff', repoPath, filePath),
    scanRepos: (roots, options) => ipcRenderer.invoke('x19:git:scanRepos', roots, options),
    review: {
      list: (repoPath, scope, baseRef) => ipcRenderer.invoke('x19:git:review:list', repoPath, scope, baseRef),
      diff: (repoPath, filePath, scope, baseRef, staged) =>
        ipcRenderer.invoke('x19:git:review:diff', repoPath, filePath, scope, baseRef, staged),
      stage: (repoPath, filePath) => ipcRenderer.invoke('x19:git:review:stage', repoPath, filePath),
      unstage: (repoPath, filePath) => ipcRenderer.invoke('x19:git:review:unstage', repoPath, filePath),
      revert: (repoPath, filePath) => ipcRenderer.invoke('x19:git:review:revert', repoPath, filePath),
      revParse: (repoPath, ref) => ipcRenderer.invoke('x19:git:review:revParse', repoPath, ref),
      commit: (repoPath, message, push) => ipcRenderer.invoke('x19:git:review:commit', repoPath, message, push),
      commitContext: repoPath => ipcRenderer.invoke('x19:git:review:commitContext', repoPath),
      push: repoPath => ipcRenderer.invoke('x19:git:review:push', repoPath),
      shipInfo: repoPath => ipcRenderer.invoke('x19:git:review:shipInfo', repoPath),
      prList: (repoPath, branches, numbers) =>
        ipcRenderer.invoke('x19:git:review:prList', repoPath, branches, numbers),
      createPr: repoPath => ipcRenderer.invoke('x19:git:review:createPr', repoPath)
    }
  },
  terminal: {
    attach: id => ipcRenderer.invoke('x19:terminal:attach', id),
    cwd: id => ipcRenderer.invoke('x19:terminal:cwd', id),
    dispose: id => ipcRenderer.invoke('x19:terminal:dispose', id),
    resize: (id, size) => ipcRenderer.invoke('x19:terminal:resize', id, size),
    start: options => ipcRenderer.invoke('x19:terminal:start', options),
    write: (id, data) => ipcRenderer.invoke('x19:terminal:write', id, data),
    onData: (id, callback) => {
      const channel = `x19:terminal:${id}:data`
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on(channel, listener)

      return () => ipcRenderer.removeListener(channel, listener)
    },
    onExit: (id, callback) => {
      const channel = `x19:terminal:${id}:exit`
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on(channel, listener)

      return () => ipcRenderer.removeListener(channel, listener)
    }
  },
  onClosePreviewRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:close-preview-requested', listener)

    return () => ipcRenderer.removeListener('x19:close-preview-requested', listener)
  },
  onPreviewNav: callback => {
    const listener = (_event, command) => callback(command)
    ipcRenderer.on('x19:preview-nav', listener)

    return () => ipcRenderer.removeListener('x19:preview-nav', listener)
  },
  onOpenFolderRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:open-folder-requested', listener)

    return () => ipcRenderer.removeListener('x19:open-folder-requested', listener)
  },
  onOpenUpdatesRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:open-updates', listener)

    return () => ipcRenderer.removeListener('x19:open-updates', listener)
  },
  onDeepLink: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:deep-link', listener)

    return () => ipcRenderer.removeListener('x19:deep-link', listener)
  },
  signalDeepLinkReady: () => ipcRenderer.invoke('x19:deep-link-ready'),
  probePluginRepo: payload => ipcRenderer.invoke('x19:plugin:probe', payload),
  installDesktopPlugin: payload => ipcRenderer.invoke('x19:plugin:installDesktop', payload),
  onWindowStateChanged: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:window-state-changed', listener)

    return () => ipcRenderer.removeListener('x19:window-state-changed', listener)
  },
  onFocusSession: callback => {
    const listener = (_event, sessionId) => callback(sessionId)
    ipcRenderer.on('x19:focus-session', listener)

    return () => ipcRenderer.removeListener('x19:focus-session', listener)
  },
  onNotificationAction: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:notification-action', listener)

    return () => ipcRenderer.removeListener('x19:notification-action', listener)
  },
  onNotificationActivate: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:notification-activate', listener)

    return () => ipcRenderer.removeListener('x19:notification-activate', listener)
  },
  onPreviewFileChanged: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:preview-file-changed', listener)

    return () => ipcRenderer.removeListener('x19:preview-file-changed', listener)
  },
  onBackendExit: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:backend-exit', listener)

    return () => ipcRenderer.removeListener('x19:backend-exit', listener)
  },
  // Cooperative pool retirement (main → renderer): the pooled backend under
  // `poolKey` is being stopped for a foreground open. Park that scope; do not
  // redial into the slot it vacated.
  onPoolBackendRetiring: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:pool:retiring', listener)

    return () => ipcRenderer.removeListener('x19:pool:retiring', listener)
  },
  // Soft gateway-mode apply finished tearing down the primary backend. Renderer
  // should wipe session lists + re-dial without a window reload.
  onConnectionApplied: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:connection:applied', listener)

    return () => ipcRenderer.removeListener('x19:connection:applied', listener)
  },
  onPowerResume: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:power-resume', listener)

    return () => ipcRenderer.removeListener('x19:power-resume', listener)
  },
  // AC ↔ battery transitions; renderers slow their backstop polls on battery.
  getOnBattery: () => ipcRenderer.invoke('x19:power-battery:get'),
  onBatteryChanged: callback => {
    const listener = (_event, onBattery) => callback(Boolean(onBattery))
    ipcRenderer.on('x19:power-battery', listener)

    return () => ipcRenderer.removeListener('x19:power-battery', listener)
  },
  onBootProgress: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:boot-progress', listener)

    return () => ipcRenderer.removeListener('x19:boot-progress', listener)
  },
  // First-launch bootstrap progress -- emitted by the install.ps1 stage
  // runner in main.ts (apps/desktop/electron/bootstrap-runner.ts).
  // Renderer's install overlay subscribes to live events and queries the
  // current snapshot via getBootstrapState() to recover after a devtools
  // reload mid-bootstrap.
  getBootstrapState: () => ipcRenderer.invoke('x19:bootstrap:get'),
  continueBootstrapLocal: () => ipcRenderer.invoke('x19:bootstrap:continue-local'),
  recycleBackend: profile => ipcRenderer.invoke('x19:backend:recycle', profile),
  resetBootstrap: () => ipcRenderer.invoke('x19:bootstrap:reset'),
  repairBootstrap: () => ipcRenderer.invoke('x19:bootstrap:repair'),
  cancelBootstrap: () => ipcRenderer.invoke('x19:bootstrap:cancel'),
  onBootstrapEvent: callback => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('x19:bootstrap:event', listener)

    return () => ipcRenderer.removeListener('x19:bootstrap:event', listener)
  },
  getVersion: () => ipcRenderer.invoke('x19:version'),
  relaunchApp: () => ipcRenderer.invoke('x19:app:relaunch'),
  getMachineProfile: () => ipcRenderer.invoke('x19:machine:profile'),
  getRemoteDisplayReason: () => ipcRenderer.invoke('x19:get-remote-display-reason'),
  uninstall: {
    summary: () => ipcRenderer.invoke('x19:uninstall:summary'),
    run: mode => ipcRenderer.invoke('x19:uninstall:run', { mode })
  },
  updates: {
    check: opts => ipcRenderer.invoke('x19:updates:check', opts),
    apply: opts => ipcRenderer.invoke('x19:updates:apply', opts),
    getBranch: () => ipcRenderer.invoke('x19:updates:branch:get'),
    setBranch: name => ipcRenderer.invoke('x19:updates:branch:set', name),
    onProgress: callback => {
      const listener = (_event, payload) => callback(payload)
      ipcRenderer.on('x19:updates:progress', listener)

      return () => ipcRenderer.removeListener('x19:updates:progress', listener)
    }
  },
  themes: {
    fetchMarketplace: id => ipcRenderer.invoke('x19:vscode-theme:fetch', id),
    searchMarketplace: query => ipcRenderer.invoke('x19:vscode-theme:search', query)
  },
  // Find-in-page (Ctrl/Cmd+F): delegates to Electron's
  // webContents.findInPage on the IPC sender's window so a Cmd+F pressed
  // in a secondary session window searches THAT window, not the primary.
  // `onFoundInPage` returns the unsubscribe fn; the renderer wires it via
  // `initFindInPageListener` in store/find-in-page.ts and tears it down
  // when the FindBar unmounts.
  findInPage: (query, options) => ipcRenderer.invoke('x19:find-in-page', query, options),
  stopFindInPage: () => ipcRenderer.invoke('x19:stop-find-in-page'),
  onFoundInPage: callback => {
    const listener = (_event, result) => callback(result)
    ipcRenderer.on('x19:found-in-page', listener)

    return () => ipcRenderer.removeListener('x19:found-in-page', listener)
  },
  // Main-process `before-input-event` forwards Ctrl/Cmd+F here so renderer
  // can open the FindBar even when the GTK compositor has already grabbed
  // the chord at the windowing layer (#81727).
  onOpenFindBarRequested: callback => {
    const listener = () => callback()
    ipcRenderer.on('x19:open-find-bar', listener)

    return () => ipcRenderer.removeListener('x19:open-find-bar', listener)
  }
})
