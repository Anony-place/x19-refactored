# Bundled plugins

Drop a `<name>/plugin.{ts,tsx}` here that default-exports a `X19Plugin` and
it registers automatically at boot (vite glob in `../contrib/plugins.ts`), with
the same inventory + live enable/disable contract as runtime plugins.

Keep this tree for real shipped plugins (and the small authoring fixtures that
dogfood the SDK). One-off demos that rebuild a core chrome piece 1:1 do not
belong here — they double the UI and confuse Capabilities ▸ Plugins. Publish those
in the companion
[`x19-example-plugins`](https://github.com/Anony-place/x19-refactored-plugins)
repo instead.

User- and agent-authored plugins load at runtime from
`$X19_HOME/desktop-plugins/<name>/plugin.js` (the disk door) — see the
`x19-desktop-plugins` skill.
