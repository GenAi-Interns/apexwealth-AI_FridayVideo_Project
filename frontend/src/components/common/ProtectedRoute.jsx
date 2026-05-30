import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function ProtectedRoute({ children, allowedRoles }) {
  const { user } = useAuth();

  if (!user) {
    // If not logged in, redirect to login page
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    // If logged in but role mismatch, redirect to their proper default home page
    return <Navigate to={user.role === 'Admin' ? "/dashboard" : "/chat"} replace />;
  }

  return children;
}
