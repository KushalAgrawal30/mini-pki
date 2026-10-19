import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { useSession } from '../App.jsx'
import { Flash } from '../components.jsx'

const pemToDer = (pem) => Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, '')), (c) => c.charCodeAt(0))

export default function Login() {
  const [certFile, setCertFile] = useState(null)
  const [keyFile, setKeyFile] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { setMe } = useSession()
  const navigate = useNavigate()
  const renewed = useLocation().state?.renewed

  const submit = async (e) => {
    e.preventDefault()
    setError(''); setBusy(true)
    try {
      const keyPem = await keyFile.text()
      if (!keyPem.includes('BEGIN PRIVATE KEY')) throw new Error('Key must be an unencrypted PKCS#8 PEM ("BEGIN PRIVATE KEY")')
      // Private key is used only inside the browser (WebCrypto); it is never sent to the server.
      const key = await crypto.subtle.importKey('pkcs8', pemToDer(keyPem), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      const { challenge } = await api('/api/login/challenge')
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(challenge))
      const me = await api('/api/login', {
        cert_pem: await certFile.text(),
        signature: btoa(String.fromCharCode(...new Uint8Array(sig))),
      })
      setMe(me)
      navigate(me.role === 'admin' ? '/admin' : '/portal')
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <div className="card">
      <h1>Log in with your certificate</h1>
      {renewed && (
        <div className="flash ok">Certificate renewed. <a href={`/cert/${renewed}.pem`} download>Download the new certificate</a> and log in with it and your new key.</div>
      )}
      <p>Your browser signs a one-time challenge from the server with your private key. Only the certificate and the
        signature are sent; <strong>the private key never leaves this page</strong>. The server then checks the chain,
        validity period, key usage, revocation (CRL) and the signature.</p>
      <Flash error={error} />
      <form onSubmit={submit}>
        <label htmlFor="cert">Certificate (.pem)</label>
        <input id="cert" type="file" accept=".pem,.crt,.cer" required onChange={(e) => setCertFile(e.target.files[0])} />
        <label htmlFor="key">Private key (.pem, unencrypted PKCS#8)</label>
        <input id="key" type="file" accept=".pem,.key" required onChange={(e) => setKeyFile(e.target.files[0])} />
        <button className="btn" disabled={busy}>{busy ? 'Verifying…' : 'Sign challenge & log in'}</button>
      </form>
    </div>
  )
}
