import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { useSession } from '../App.jsx'
import { CertLink, Flash, Pill } from '../components.jsx'

export default function Portal() {
  const { me, refresh } = useSession()
  const [certs, setCerts] = useState([])
  const [csr, setCsr] = useState('')
  const [msg, setMsg] = useState({})
  const navigate = useNavigate()
  const load = () => api('/api/my/certs').then(setCerts, (e) => setMsg({ error: e.message }))
  useEffect(() => { load() }, [])

  const revoke = async (serial, reason) => {
    if (!confirm(`Revoke ${serial}? This cannot be undone.`)) return
    try {
      const { logged_out } = await api('/api/my/revoke', { serial, reason })
      if (logged_out) { await refresh(); navigate('/') } else { setMsg({ ok: 'Certificate revoked.' }); load() }
    } catch (e) { setMsg({ error: e.message }) }
  }

  const renew = async (e) => {
    e.preventDefault()
    try {
      const { serial } = await api('/api/my/renew', { csr })
      await refresh()
      navigate('/login', { state: { renewed: serial } })
    } catch (err) { setMsg({ error: err.message }) }
  }

  return (
    <>
      <div className="card">
        <h1>Welcome, {me.user}</h1>
        <p>You are authenticated by <strong>{me.method}</strong>
          {me.serial && <> (serial <code>{me.serial}</code>)</>}. This is the protected application area.</p>
      </div>
      <Flash {...msg} />
      <div className="card">
        <h2>My certificates</h2>
        <div className="table-wrap"><table>
          <thead><tr><th>Serial</th><th>Expires</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.serial}>
                <td><code>{c.serial}</code></td><td>{c.not_after}</td>
                <td><Pill status={c.status} /> {c.reason && <span className="muted">{c.reason}</span>}</td>
                <td><CertLink serial={c.serial} />
                  {c.status === 'valid' && <RevokeForm reasons={me.reasons} onRevoke={(r) => revoke(c.serial, r)} />}
                </td>
              </tr>
            ))}
            {!certs.length && <tr><td colSpan="4" className="muted">No certificates.</td></tr>}
          </tbody>
        </table></div>
      </div>
      {me.method === 'certificate' && (
        <div className="card">
          <h2>Renew certificate</h2>
          <p>Generate a <strong>new</strong> key and CSR and paste the CSR below. Your current certificate will be revoked as <code>superseded</code>.</p>
          <form onSubmit={renew}>
            <label htmlFor="csr">New CSR (PEM)</label>
            <textarea id="csr" required value={csr} onChange={(e) => setCsr(e.target.value)} />
            <button className="btn">Renew</button>
          </form>
        </div>
      )}
    </>
  )
}

export function RevokeForm({ reasons, onRevoke }) {
  const [reason, setReason] = useState(reasons[0])
  return (
    <span className="inline">
      <select aria-label="Revocation reason" value={reason} onChange={(e) => setReason(e.target.value)}>
        {reasons.map((r) => <option key={r}>{r}</option>)}
      </select>
      <button className="btn danger" onClick={() => onRevoke(reason)}>Revoke</button>
    </span>
  )
}
