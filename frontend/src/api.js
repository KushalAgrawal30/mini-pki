// GET when no data, POST JSON otherwise. Every POST carries the session's CSRF token.
export async function api(path, data) {
  let opts = {}
  if (data !== undefined) {
    const { csrf } = await (await fetch('/api/me')).json() // fresh token: the server rotates it on login/logout
    opts = { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(data) }
  }
  const res = await fetch(path, opts)
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(json.error || res.statusText)
  return json
}
