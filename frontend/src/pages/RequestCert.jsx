import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { Flash } from '../components.jsx'

export default function RequestCert() {
  const [form, setForm] = useState({ username: '', email: '', csr: '' })
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  const submit = async (e) => {
    e.preventDefault()
    try {
      const { id } = await api('/api/requests', form)
      navigate(`/request/${id}`)
    } catch (err) { setError(err.message) }
  }

  return (
    <div className="card">
      <h1>Request a certificate</h1>
      <p>Generate your key pair <strong>on your own machine</strong>. Your private key never leaves it.</p>
      <pre>{`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out mykey.pem
openssl req -new -key mykey.pem -subj "/CN=yourname" -out my.csr
cat my.csr`}</pre>
      <Flash error={error} />
      <form onSubmit={submit}>
        <label htmlFor="username">Username</label>
        <input id="username" required value={form.username} onChange={set('username')} />
        <label htmlFor="email">Email</label>
        <input id="email" type="email" required value={form.email} onChange={set('email')} />
        <label htmlFor="csr">Certificate Signing Request (PEM)</label>
        <textarea id="csr" required placeholder="-----BEGIN CERTIFICATE REQUEST-----" value={form.csr} onChange={set('csr')} />
        <button className="btn">Submit to Registration Authority</button>
      </form>
    </div>
  )
}
