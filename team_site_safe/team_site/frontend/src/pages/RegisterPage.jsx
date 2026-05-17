import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authAPI } from '../utils/api';

export default function RegisterPage() {
  const [form, setForm]     = useState({ username: '', password: '', email: '' });
  const [msg, setMsg]       = useState({ type: '', text: '' });
  const [loading, setLoading] = useState(false);
  const navigate            = useNavigate();

  const handleChange = e => setForm({ ...form, [e.target.name]: e.target.value });

  // [VULN] 비밀번호 복잡도 검증 없음 — "1"도 가입 가능
  const handleSubmit = async () => {
    setMsg({ type: '', text: '' });
    if (!form.username || !form.password) {
      return setMsg({ type: 'error', text: '아이디와 비밀번호를 입력하세요.' });
    }
    setLoading(true);
    try {
      await authAPI.register(form);
      setMsg({ type: 'success', text: '회원가입이 완료되었습니다. 로그인하세요.' });
      setTimeout(() => navigate('/login'), 1500);
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.detail || '회원가입에 실패했습니다.' });
    } finally { setLoading(false); }
  };

  return (
    <div className="auth-page">
      <div className="auth-left">
        <div className="auth-left-content">
          <div className="auth-left-logo">NeoBanK</div>
          <h1 className="auth-left-title">빠르고 안전한<br />금융 서비스</h1>
          <p className="auth-left-desc">
            30초 만에 계정을 만들고<br />
            NeoBanK의 모든 서비스를 이용하세요.
          </p>
          <div style={{ marginTop: 40, padding: '20px 24px', borderRadius: 14, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <p style={{ fontSize: 13, color: 'var(--gray-300)', lineHeight: 1.8 }}>
              ✓ 무료 계좌 개설<br />
              ✓ 즉시 이체 서비스<br />
              ✓ 실시간 환율 조회<br />
              ✓ 24/7 고객 지원
            </p>
          </div>
        </div>
      </div>

      <div className="auth-right">
        <div className="auth-box">
          <h2 className="auth-box-title">회원가입</h2>
          <p className="auth-box-sub">새 NeoBanK 계정을 만드세요</p>

          {msg.text && (
            <div className={`alert alert-${msg.type === 'error' ? 'error' : 'success'}`}>
              {msg.text}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">아이디</label>
            <input
              className="form-input"
              name="username"
              placeholder="사용할 아이디"
              value={form.username}
              onChange={handleChange}
              autoComplete="off"
            />
          </div>
          <div className="form-group">
            <label className="form-label">
              비밀번호
              {/* [VULN] 안내 없음 — 복잡도 요구사항 없음 */}
            </label>
            <input
              className="form-input"
              name="password"
              type="password"
              placeholder="비밀번호 (제한 없음)"
              value={form.password}
              onChange={handleChange}
            />
            <p style={{ fontSize: 12, color: 'var(--gray-300)', marginTop: 6 }}>
              * 비밀번호 형식 제한 없음
            </p>
          </div>
          <div className="form-group">
            <label className="form-label">이메일 (선택)</label>
            <input
              className="form-input"
              name="email"
              type="email"
              placeholder="example@email.com"
              value={form.email}
              onChange={handleChange}
            />
          </div>

          <button
            className="btn btn-gold btn-full btn-lg"
            onClick={handleSubmit}
            disabled={loading}
          >
            {loading ? '처리 중...' : '계정 만들기'}
          </button>

          <div className="divider" />

          <p style={{ textAlign: 'center', fontSize: 14, color: 'var(--gray-500)' }}>
            이미 계정이 있으신가요?{' '}
            <Link to="/login" style={{ color: 'var(--navy)', fontWeight: 600, textDecoration: 'none' }}>
              로그인
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
