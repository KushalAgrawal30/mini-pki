import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Flash } from '../components.jsx'

export default function Audit() {
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')
  useEffect(() => { api('/api/admin/audit').then(setRows, (e) => setError(e.message)) }, [])
  return (
    <div className="card">
      <h1>Audit log</h1>
      <Flash error={error} />
      <div className="table-wrap"><table>
        <thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}><td>{r.ts}</td><td>{r.actor}</td><td>{r.action}</td><td>{r.detail}</td><td>{r.ip}</td></tr>
          ))}
        </tbody>
      </table></div>
    </div>
  )
}
