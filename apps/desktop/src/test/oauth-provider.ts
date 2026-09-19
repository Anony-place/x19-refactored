import type { OAuthProvider } from '@/types/x19'

/** A logged-out PKCE provider. Onboarding branches on `flow` and
 *  `status.logged_in`; the rest is filler the UI only echoes. */
export function makeOAuthProvider(id: string, name = id): OAuthProvider {
  return {
    cli_command: `x19 login ${id}`,
    docs_url: `https://example.com/${id}`,
    flow: 'pkce',
    id,
    name,
    status: { logged_in: false }
  }
}
