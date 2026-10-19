import { Link } from 'react-router-dom'

export default function Home() {
  return (
    <>
      <div className="card">
        <h1>Mini Public Key Infrastructure</h1>
        <p>Certificate-based authentication for the organization. Trust hierarchy:</p>
        <pre>{`MiniPKI Root CA  (self-signed trust anchor, ECC P-384)
   └── MiniPKI Intermediate CA  (issues end-entity certs, signs CRL)
         ├── localhost  (this server's HTTPS certificate)
         └── user / device certificates  (ECC P-256, clientAuth)`}</pre>
        <Link className="btn" to="/request">1. Request a certificate</Link>{' '}
        <Link className="btn" to="/login">2. Log in with certificate</Link>
      </div>
      <div className="card">
        <h2>Public CA endpoints</h2>
        <ul>
          <li><a href="/ca/root.pem">Root CA certificate</a> (install as a trusted root)</li>
          <li><a href="/ca/chain.pem">CA chain (Intermediate + Root)</a></li>
          <li><a href="/crl.pem">Certificate Revocation List</a></li>
        </ul>
      </div>
    </>
  )
}
