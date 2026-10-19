export const Pill = ({ status }) => <span className={`pill ${status}`}>{status}</span>

export const Flash = ({ error, ok }) => (
  <>
    {error && <div className="flash error">{error}</div>}
    {ok && <div className="flash ok">{ok}</div>}
  </>
)

export const CertLink = ({ serial }) => <a href={`/cert/${serial}.pem`} download>Download</a>
