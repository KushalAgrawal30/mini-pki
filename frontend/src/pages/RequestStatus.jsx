import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { Flash, Pill } from '../components.jsx'

export default function RequestStatus() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const load = () => api(`/api/requests/${id}`).then(setData, (e) => setError(e.message))
  useEffect(() => { load() }, [id])

  if (error) return <Flash error={error} />
  if (!data) return null
  const { request: req, cert } = data
  return (
    <div className="card">
      <h1>Request for {req.username} <Pill status={req.status} /></h1>
      <p className="muted">Bookmark this page: it is the only way to check this request. Submitted {req.created}</p>
      {req.status === 'pending' && (
        <p>Waiting for the Registration Authority to verify your identity.{' '}
          <button className="btn secondary" onClick={load}>Check again</button></p>
      )}
      {req.status === 'rejected' && <p>Rejected by {req.reviewed_by}: {req.note || 'no reason given'}</p>}
      {cert && (
        <>
          <p>Serial <code>{cert.serial}</code>, status <Pill status={cert.status} />, expires {cert.not_after}</p>
          <a className="btn" href={`/cert/${cert.serial}.pem`} download>Download certificate</a>{' '}
          <a className="btn secondary" href="/ca/chain.pem">Download CA chain</a>{' '}
          <Link className="btn secondary" to="/login">Log in</Link>
        </>
      )}
    </div>
  )
}
