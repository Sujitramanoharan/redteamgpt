import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { api } from './api';

const AuthContext = createContext(null);
const RANK = { member: 1, admin: 2, owner: 3 };

export function AuthProvider({ children }) {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setMe(await api.get('/api/auth/me'));
    } catch {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => setMe(null);
    window.addEventListener('rtg:unauthorized', onUnauthorized);
    return () => window.removeEventListener('rtg:unauthorized', onUnauthorized);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/api/auth/logout');
    } finally {
      setMe(null);
    }
  }, []);

  // Role checks for hiding controls. The server enforces the same rules;
  // this only keeps people from clicking buttons that will be refused.
  const can = useCallback((role) => (RANK[me?.user?.role] || 0) >= RANK[role], [me]);

  return (
    <AuthContext.Provider value={{ me, setMe, loading, refresh, logout, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

export function FullPageLoader() {
  return (
    <div className="auth-shell">
      <div className="spinner" aria-label="Loading" />
    </div>
  );
}

export function RequireAuth({ children }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <FullPageLoader />;
  if (!me) {
    return <Navigate to={`/login?next=${encodeURIComponent(location.pathname)}`} replace />;
  }
  return children;
}
