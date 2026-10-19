import { createContext, useContext, useEffect, useState } from 'react'
import { Link, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { api } from './api.js'
import Home from './pages/Home.jsx'
import RequestCert from './pages/RequestCert.jsx'
import RequestStatus from './pages/RequestStatus.jsx'
import Login from './pages/Login.jsx'
import Portal from './pages/Portal.jsx'
import AdminLogin from './pages/AdminLogin.jsx'
import Admin from './pages/Admin.jsx'
import Audit from './pages/Audit.jsx'

const Session = createContext(null)
export const useSession = () => useContext(Session)

function Guard({ role, children }) {
  const { me } = useSession()
  if (!me.user) return <Navigate to={role === 'admin' ? '/admin/login' : '/login'} replace />
  if (role && me.role !== role) return <p className="card">Forbidden: requires {role} role.</p>
  return children
}

export default function App() {
  const [me, setMe] = useState(null)
  const navigate = useNavigate()
  const refresh = () => api('/api/me').then(setMe)
  useEffect(() => { refresh() }, [])

  if (!me) return null
  const logout = async () => { setMe(await api('/api/logout', {})); navigate('/') }

  return (
    <Session.Provider value={{ me, setMe, refresh }}>
      <nav>
        <Link className="brand" to="/">Mini PKI</Link>
        <Link to="/request">Request certificate</Link>
        {me.user ? (
          <>
            <Link to="/portal">Portal</Link>
            {me.role === 'admin' && <><Link to="/admin">Admin</Link><Link to="/admin/audit">Audit log</Link></>}
            <button onClick={logout}>Logout ({me.user})</button>
          </>
        ) : (
          <>
            <Link to="/login">Certificate login</Link>
            <Link to="/admin/login">Admin</Link>
          </>
        )}
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/request" element={<RequestCert />} />
          <Route path="/request/:id" element={<RequestStatus />} />
          <Route path="/login" element={<Login />} />
          <Route path="/portal" element={<Guard><Portal /></Guard>} />
          <Route path="/admin/login" element={<AdminLogin />} />
          <Route path="/admin" element={<Guard role="admin"><Admin /></Guard>} />
          <Route path="/admin/audit" element={<Guard role="admin"><Audit /></Guard>} />
          <Route path="*" element={<p className="card">Page not found.</p>} />
        </Routes>
      </main>
    </Session.Provider>
  )
}
