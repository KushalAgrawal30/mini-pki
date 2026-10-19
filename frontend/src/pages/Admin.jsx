import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { useSession } from '../App.jsx'
import { CertLink, Flash, Pill } from '../components.jsx'
import { RevokeForm } from './Portal.jsx'

export default function Admin() {
  const { me } = useSession()
  const [pending, setPending] = useState([])
  const [certs, setCerts] = useState([])
  const [msg, setMsg] = useState({})

  const load = () => Promise.all([api('/api/admin/requests'), api('/api/admin/certs')])
    .then(([p, c]) => { setPending(p); setCerts(c) }, (e) => setMsg({ error: e.message }))
  useEffect(() => { load() }, [])

  const act = async (fn, ok) => {
    try { await fn(); setMsg({ ok }); load() } catch (e) { setMsg({ error: e.message }) }
  }

  return (
    <>
      <Flash {...msg} />
      <div className="card">
        <h1>Pending certificate requests (Registration Authority)</h1>
        <p className="muted">Verify the applicant's identity out of band before approving. Tip: validity 0.001 days (~90 s) demos expiry.</p>
        <div className="table-wrap"><table>
          <thead><tr><th>User</th><th>Email</th><th>Submitted</th><th>CSR</th><th>Decision</th></tr></thead>
          <tbody>
            {pending.map((r) => (
              <PendingRow key={r.id} r={r}
                onApprove={(days) => act(() => api(`/api/admin/requests/${r.id}`, { action: 'approve', days }), `Issued certificate to ${r.username}`)}
                onReject={(note) => act(() => api(`/api/admin/requests/${r.id}`, { action: 'reject', note }), `Rejected ${r.username}`)} />
            ))}
            {!pending.length && <tr><td colSpan="5" className="muted">No pending requests.</td></tr>}
          </tbody>
        </table></div>
      </div>
      <div className="card">
        <h2>Issued certificates</h2>
        <div className="table-wrap"><table>
          <thead><tr><th>Serial</th><th>User</th><th>Expires</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.serial}>
                <td><code>{c.serial}</code></td><td>{c.username}</td><td>{c.not_after}</td>
                <td><Pill status={c.status} /> {c.reason && <span className="muted">{c.reason}</span>}</td>
                <td><CertLink serial={c.serial} />
                  {!c.revoked_at && <RevokeForm reasons={me.reasons} onRevoke={(reason) => confirm(`Revoke ${c.serial}?`) &&
                    act(() => api('/api/admin/revoke', { serial: c.serial, reason }), `Revoked ${c.serial}`)} />}
                </td>
              </tr>
            ))}
            {!certs.length && <tr><td colSpan="5" className="muted">None yet.</td></tr>}
          </tbody>
        </table></div>
      </div>
    </>
  )
}

function PendingRow({ r, onApprove, onReject }) {
  const [days, setDays] = useState('365')
  const [note, setNote] = useState('')
  return (
    <tr>
      <td>{r.username}</td><td>{r.email}</td><td>{r.created}</td>
      <td><details><summary>view</summary><pre>{r.csr}</pre></details></td>
      <td>
        <span className="inline">
          <input size="5" aria-label="Validity in days" value={days} onChange={(e) => setDays(e.target.value)} /> days
          <button className="btn" onClick={() => onApprove(days)}>Approve</button>
        </span>
        <span className="inline" style={{ marginTop: 6 }}>
          <input placeholder="reason" aria-label="Rejection reason" value={note} onChange={(e) => setNote(e.target.value)} />
          <button className="btn danger" onClick={() => onReject(note)}>Reject</button>
        </span>
      </td>
    </tr>
  )
}
