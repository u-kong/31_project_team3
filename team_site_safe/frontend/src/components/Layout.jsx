import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const NAV = [
  { path: '/dashboard', icon: '▦', label: '대시보드' },
  { path: '/accounts',  icon: '⬡', label: '계좌 조회' },
  { path: '/transfer',  icon: '⇄', label: '계좌 이체' },
  { path: '/exchange',  icon: '◈', label: '환율 조회' },
];

// JWT payload에서 role 추출 (변조 반영)
function getTokenRole() {
  try {
    const token = localStorage.getItem('token') || '';
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.role || 'user';
  } catch { return 'user'; }
}

export default function Layout({ children }) {
  const navigate  = useNavigate();
  const location  = useLocation();
  const user      = JSON.parse(localStorage.getItem('user') || '{}');
  const tokenRole = getTokenRole();

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-mark">NeoBanK</div>
          <div className="logo-sub">Smart Finance</div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">메뉴</div>
          {NAV.map(n => (
            <button
              key={n.path}
              className={`nav-item ${location.pathname === n.path ? 'active' : ''}`}
              onClick={() => navigate(n.path)}
            >
              <span className="nav-icon">{n.icon}</span>
              {n.label}
            </button>
          ))}

          {/* JWT role=admin일 때만 노출 — 변조하면 일반 유저도 보임 (BAC) */}
          {tokenRole === 'admin' && (
            <>
              <div className="nav-section-label" style={{ marginTop: 12 }}>관리자</div>
              <button
                className={`nav-item ${location.pathname === '/admin' ? 'active' : ''}`}
                onClick={() => navigate('/admin')}
                style={{ color: 'var(--gold)' }}
              >
                <span className="nav-icon">⚙</span>
                관리자 페이지
                <span className="badge badge-red" style={{ marginLeft: 'auto', fontSize: 10 }}>ADMIN</span>
              </button>
            </>
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-avatar">
              {(user.username || 'U')[0].toUpperCase()}
            </div>
            <div>
              <div className="user-name">{user.username || 'Unknown'}</div>
              <div className="user-role">{user.role || 'user'}</div>
            </div>
            <button
              onClick={logout}
              style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--gray-500)', cursor: 'pointer', fontSize: 16 }}
              title="로그아웃"
            >
              ⏻
            </button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        {children}
      </main>
    </div>
  );
}
