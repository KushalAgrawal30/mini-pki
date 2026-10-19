import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { useSession } from '../App.jsx'
import { Flash } from '../components.jsx'

export default function AdminLogin() {
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  const { setMe } = useSession()
  const navigate = useNavigate()

  const submit = async (e) => {
    e.preventDefault()
    try {
      setMe(await api('/api/admin/login', form))
      navigate('/admin')
    } catch (err) { setError(err.message) }
  }

  return (
    <div className="card narrow">
      <h1>Administrator login</h1>
      <Flash error={error} />
      <form onSubmit={submit}>
        <label htmlFor="u">Username</label>
        <input id="u" required autoComplete="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <label htmlFor="p">Password</label>
        <input id="p" type="password" required autoComplete="current-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button className="btn">Log in</button>
      </form>
    </div>
  )
}
