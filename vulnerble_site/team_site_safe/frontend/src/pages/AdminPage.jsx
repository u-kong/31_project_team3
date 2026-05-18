import React, { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { adminAPI } from '../utils/api';

function fmt(n) { return Number(n).toLocaleString('ko-KR') + '원'; }

export default function AdminPage() {
  const [tab,    setTab]    = useState('users');
  const [users,  setUsers]  = useState([]);
  const [accs,   setAccs]   = useState([]);
  const [txns,   setTxns]   = useState([]);
  const [msg,    setMsg]    = useState('');

  // [VULN] Broken Access Control: 토큰 없어도 /admin/* 에서 데이터 반환
  useEffect(() => {
    adminAPI.users().then(r => setUsers(r.data)).catch(() => {});
    adminAPI.accounts().then(r => setAccs(r.data)).catch(() => {});
    adminAPI.transactions().then(r => setTxns(r.data)).catch(() => {});
  }, []);

  const handleDelete = async (id) => {
    if (!window.confirm(`User #${id}를 삭제하시겠습니까?`)) return;
    try {
      await adminAPI.deleteUser(id);
      setUsers(prev => prev.filter(u => u.id !== id));
      setMsg(`User #${id} 삭제 완료`);
    } catch (e) {
      setMsg('삭제 실패: ' + (e.response?.data?.detail || ''));
    }
  };

  const TABS = [
    { key: 'users',   label: `유저 (${users.length})` },
    { key: 'accounts',label: `계좌 (${accs.length})` },
    { key: 'txns',    label: `거래 (${txns.length})` },
  ];

  return (
    <Layout>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h1 className="page-title">관리자 패널</h1>
          <span className="badge badge-red" style={{ fontSize: 12 }}>인증 없이 접근 가능</span>
        </div>
        <p className="page-subtitle">/admin/* 엔드포인트는 인증/인가 없이 누구나 접근할 수 있습니다.</p>
      </div>

      <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '12px 16px', marginBottom: 24, fontSize: 13, color: '#dc2626' }}>
        ⚠ Broken Access Control: 이 페이지는 로그인하지 않아도, 일반 유저도 접근 가능합니다. (토큰 검증 없음)
      </div>

      {msg && <div className="alert alert-info">{msg}</div>}

      {/* 탭 */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`btn ${tab === t.key ? 'btn-primary' : 'btn-ghost'} btn-sm`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* 유저 테이블 */}
      {tab === 'users' && (
        <div className="card">
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, marginBottom: 16 }}>전체 유저 (비밀번호 포함)</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>아이디</th><th>이메일</th><th>비밀번호</th><th>권한</th><th>가입일</th><th>관리</th></tr></thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td><span className="badge badge-gray">#{u.id}</span></td>
                    <td style={{ fontWeight: 600 }}>{u.username}</td>
                    <td style={{ fontSize: 12 }}>{u.email}</td>
                    <td>
                      <code style={{ background: 'rgba(239,68,68,0.08)', color: '#dc2626', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>
                        {u.password}
                      </code>
                    </td>
                    <td>
                      <span className={`badge ${u.role === 'admin' ? 'badge-gold' : 'badge-blue'}`}>
                        {u.role}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--gray-500)' }}>{u.created_at?.substring(0, 10)}</td>
                    <td>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete(u.id)}>삭제</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 계좌 테이블 */}
      {tab === 'accounts' && (
        <div className="card">
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, marginBottom: 16 }}>전체 계좌</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>유저 ID</th><th>계좌번호</th><th>종류</th><th>잔액</th></tr></thead>
              <tbody>
                {accs.map(a => (
                  <tr key={a.id}>
                    <td>#{a.id}</td>
                    <td>#{a.user_id}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{a.account_number}</td>
                    <td><span className="badge badge-blue">{a.account_type}</span></td>
                    <td style={{ fontWeight: 700 }}>{fmt(a.balance)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 거래 내역 */}
      {tab === 'txns' && (
        <div className="card">
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, marginBottom: 16 }}>전체 거래 내역</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>출금 계좌</th><th>입금 계좌</th><th>금액</th><th>내용</th><th>일시</th></tr></thead>
              <tbody>
                {txns.map(t => (
                  <tr key={t.id}>
                    <td>#{t.id}</td>
                    <td>{t.from_account_id}</td>
                    <td>{t.to_account_id}</td>
                    <td style={{ fontWeight: 600 }}>{fmt(t.amount)}</td>
                    <td>{t.description || '-'}</td>
                    <td style={{ fontSize: 12, color: 'var(--gray-500)' }}>{t.created_at?.substring(0, 16)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Layout>
  );
}
