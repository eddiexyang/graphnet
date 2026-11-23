import { APIError, request } from './api'
import type { State } from './model'

// The controller uses a global revision, including automatic endpoint discovery.
// Retry only after confirming that everything this edit replaces is unchanged.
//
// A save can be applied while its response is lost, as when the connection
// drops before the answer arrives. The next attempt then meets a newer
// revision and a configuration that no longer matches the edit's base. So
// after a conflict or a lost response, a configuration that already equals
// what was saved counts as saved.
export async function saveConfiguration(
  path: string,
  options: { method: string; body: unknown; csrf: string; revision: number },
  unchanged: (state: State) => boolean,
  updated: (state: State) => void,
  saved: (state: State) => boolean,
): Promise<State> {
  let revision = options.revision
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await request<State>(path, { ...options, revision })
    } catch (error) {
      const conflict = error instanceof APIError && error.status === 409
      const lost = !(error instanceof APIError) || error.unreadable
      if (!conflict && !lost) throw error
      let latest: State
      try {
        latest = await request<State>('/state')
      } catch {
        throw error
      }
      updated(latest)
      if (saved(latest)) return latest
      if (!conflict) throw error
      if (!unchanged(latest))
        throw new APIError(
          409,
          'These settings changed while you were editing. Your draft is preserved.',
        )
      revision = latest.revision
    }
  }
  throw new APIError(
    409,
    'Configuration is updating frequently. Your draft is preserved; please save again.',
  )
}
