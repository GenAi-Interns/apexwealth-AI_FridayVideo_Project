import { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/axios';

const AuthContext = createContext();

const formatError = (err) => {
  if (!err) return "An unknown error occurred";
  if (err.response?.data?.detail) {
    const detail = err.response.data.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      return detail.map(d => d.msg || JSON.stringify(d)).join(', ');
    }
    return typeof detail === 'object' ? JSON.stringify(detail) : String(detail);
  }
  return err.message || String(err);
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Restore session on mount safely
    const storedUser = localStorage.getItem('ssa_user');
    const token = localStorage.getItem('ssa_access_token');
    if (storedUser && token) {
      try {
        if (storedUser !== "undefined" && storedUser !== "null") {
          setUser(JSON.parse(storedUser));
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          localStorage.removeItem('ssa_user');
          localStorage.removeItem('ssa_access_token');
          localStorage.removeItem('ssa_refresh_token');
        }
      } catch (e) {
        console.error("Corrupted auth state in localStorage:", e);
        localStorage.removeItem('ssa_user');
        localStorage.removeItem('ssa_access_token');
        localStorage.removeItem('ssa_refresh_token');
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      setError(null);
      const res = await api.post("/auth/login", { email, password });

      const { user: userData, access_token, refresh_token } = res.data;

      if (!access_token || !userData) {
        throw new Error(res.data?.reason || res.data?.message || "Invalid login response structure");
      }

      localStorage.setItem('ssa_user', JSON.stringify(userData));
      localStorage.setItem('ssa_access_token', access_token);
      localStorage.setItem('ssa_refresh_token', refresh_token);

      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return userData;
    } catch (err) {
      setError(formatError(err));
      throw err;
    }
  };

  const register = async (email, password, name, role, department) => {
    try {
      setError(null);
      const res = await api.post("/auth/register", { email, password, name, role, department });

      const { user: userData, access_token, refresh_token } = res.data;

      if (!access_token || !userData) {
        throw new Error(res.data?.reason || res.data?.message || "Invalid registration response structure");
      }

      localStorage.setItem('ssa_user', JSON.stringify(userData));
      localStorage.setItem('ssa_access_token', access_token);
      localStorage.setItem('ssa_refresh_token', refresh_token);

      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      return userData;
    } catch (err) {
      setError(formatError(err));
      throw err;
    }
  }

  const logout = () => {
    setUser(null);
    localStorage.removeItem('ssa_user');
    localStorage.removeItem('ssa_access_token');
    localStorage.removeItem('ssa_refresh_token');
    delete api.defaults.headers.common['Authorization'];
  };

  if (loading) return null; // or a loading spinner

  return (
    <AuthContext.Provider value={{ user, login, register, logout, error }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
