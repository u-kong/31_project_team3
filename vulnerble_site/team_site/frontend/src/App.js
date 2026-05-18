import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LoginPage    from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import AccountsPage  from './pages/AccountsPage';
import TransferPage  from './pages/TransferPage';
import ExchangePage  from './pages/ExchangePage';
import AdminPage     from './pages/AdminPage';

function RequireAuth({ children }) {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"         element={<Navigate to="/login" replace />} />
        <Route path="/login"    element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/dashboard" element={<RequireAuth><DashboardPage /></RequireAuth>} />
        <Route path="/accounts"  element={<RequireAuth><AccountsPage /></RequireAuth>} />
        <Route path="/transfer"  element={<RequireAuth><TransferPage /></RequireAuth>} />
        <Route path="/exchange"  element={<RequireAuth><ExchangePage /></RequireAuth>} />
        {/* [VULN] /admin은 프론트에서도 auth 없이 접근 가능 */}
        <Route path="/admin"     element={<AdminPage />} />
      </Routes>
    </BrowserRouter>
  );
}
