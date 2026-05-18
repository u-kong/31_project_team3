import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authAPI } from '../utils/api';

export default function LoginPage() {
  const [form, setForm]     = useState({ username: '', password: '' });
  const [error, setError]   = useState('');
  const [loading, setLoading] = useState(false);
  const navigate            = useNavigate();

  const handleChange = e => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async () => {
    setError(''); setLoading(true);
    try {
      const res = await authAPI.login(form);
      // [VULN] JWT를 localStorage에 저장
      localStorage.setItem('token', res.data.access_token);
      localStorage.setItem('user',  JSON.stringify(res.data.user));
      navigate('/dashboard');
    } catch (e) {
      setError(e.response?.data?.detail || '로그인에 실패했습니다.');
    } finally { setLoading(false); }
  };

  return (
    <div className="auth-page">
      {/* 왼쪽 브랜드 패널 */}
      <div className="auth-left">
        <div className="auth-left-content">
          <div className="auth-left-logo">NeoBanK</div>
          <h1 className="auth-left-title">
            당신의 자산을<br />스마트하게 관리하세요
          </h1>
          <p className="auth-left-desc">
            NeoBanK는 최첨단 보안 기술과 직관적인 인터페이스로<br />
            개인 금융의 새로운 기준을 만들어갑니다.
          </p>
          <div style={{ marginTop: 36 }}>
            {['실시간 자산 현황 조회', '간편 계좌 이체 서비스', '글로벌 환율 모니터링', '24시간 금융 관리'].map(f => (
              <div className="auth-feature" key={f}>
                <span className="auth-feature-dot" />
                {f}
              </div>
            ))}
          </div>
          <div style={{ marginTop: 48, padding: '16px 20px', borderRadius: 12, background: 'rgba(201,168,76,0.1)', border: '1px solid rgba(201,168,76,0.2)' }}>
            <p style={{ fontSize: 11, color: 'var(--gold)', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>테스트 계정</p>
            <p style={{ fontSize: 13, color: 'var(--gray-300)', fontFamily: 'monospace', lineHeight: 1.8 }}>
              alice / alice1234<br />
              bob / bob5678<br />
              admin / admin_secret
            </p>
          </div>
        </div>
      </div>

      {/* 오른쪽 로그인 폼 */}
      <div className="auth-right">
        <div className="auth-box">
          <h2 className="auth-box-title">로그인</h2>
          <p className="auth-box-sub">NeoBanK 계정으로 로그인하세요</p>

          {error && <div className="alert alert-error">⚠ {error}</div>}

          <div className="form-group">
            <label className="form-label">아이디</label>
            <input
              className="form-input"
              name="username"
              placeholder="아이디를 입력하세요"
              value={form.username}
              onChange={handleChange}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              autoComplete="off"
            />
          </div>
          <div className="form-group">
            <label className="form-label">비밀번호</label>
            <input
              className="form-input"
              name="password"
              type="password"
              placeholder="비밀번호를 입력하세요"
              value={form.password}
              onChange={handleChange}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            />
          </div>

          {/* [VULN] 로그인 실패 횟수 제한 없음, 2FA 없음 */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 20 }}>
            <span style={{ fontSize: 13, color: 'var(--blue-accent)', cursor: 'pointer' }}>비밀번호 찾기</span>
          </div>

          <button
            className="btn btn-gold btn-full btn-lg"
            onClick={handleSubmit}
            disabled={loading}
          >
            {loading ? '로그인 중...' : '로그인'}
          </button>

          <div className="divider" />

          <p style={{ textAlign: 'center', fontSize: 14, color: 'var(--gray-500)' }}>
            계정이 없으신가요?{' '}
            <Link to="/register" style={{ color: 'var(--navy)', fontWeight: 600, textDecoration: 'none' }}>
              회원가입
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
