import React, { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import { accountAPI, transferAPI } from '../utils/api';

function fmt(n) {
  return Number(n).toLocaleString('ko-KR') + '원';
}

export default function DashboardPage() {
  const [account,  setAccount]  = useState(null);
  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const user = JSON.parse(localStorage.getItem('user') || '{}');

  useEffect(() => {
    (async () => {
      try {
        const accRes = await accountAPI.myAccounts();
        const acc = accRes.data[0] || null;
        setAccount(acc);
        if (acc) {
          const hRes = await transferAPI.history(acc.id);
          setHistory(hRes.data);
        }
      } catch (e) {
        console.error(e);
      } finally { setLoading(false); }
    })();
  }, []);

  return (
    <Layout>
      <div className="page-header">
        <h1 className="page-title">대시보드</h1>
        <p className="page-subtitle">안녕하세요, {user.username}님. 오늘도 스마트한 금융 생활을 시작하세요.</p>
      </div>

      {/* 잔액 카드 */}
      <div className="balance-card" style={{ marginBottom: 28 }}>
        <div className="balance-label">보유 잔액</div>
        <div className="balance-amount">{account ? fmt(account.balance) : '-'}</div>
        {account && (
          <div style={{ display: 'flex', gap: 24, marginTop: 16 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--gray-300)', letterSpacing: 1 }}>계좌번호</div>
              <div style={{ fontWeight: 600, color: 'var(--white)', marginTop: 2, fontFamily: 'monospace' }}>{account.account_number}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--gray-300)', letterSpacing: 1 }}>계좌 ID</div>
              <div style={{ fontWeight: 700, color: 'var(--gold)', marginTop: 2 }}>#{account.id}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--gray-300)', letterSpacing: 1 }}>종류</div>
              <div style={{ fontWeight: 600, color: 'var(--white)', marginTop: 2, textTransform: 'capitalize' }}>{account.account_type}</div>
            </div>
          </div>
        )}
      </div>

      {/* 통계 */}
      <div className="stat-grid" style={{ marginBottom: 32 }}>
        <div className="stat-card">
          <div className="stat-icon gold">↑</div>
          <div className="stat-value">{history.filter(h => h.from_account_id === account?.id).length}</div>
          <div className="stat-label">출금 건수</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon green">↓</div>
          <div className="stat-value">{history.filter(h => h.to_account_id === account?.id).length}</div>
          <div className="stat-label">입금 건수</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon blue">⬡</div>
          <div className="stat-value">{history.length}</div>
          <div className="stat-label">전체 거래</div>
        </div>
      </div>

      {/* 내 계좌 상세 */}
      {account && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 20 }}>내 계좌</h3>
          {loading ? <p style={{ color: 'var(--gray-500)' }}>불러오는 중...</p> : (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 0' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>
                  {account.account_type === 'checking' ? '입출금' : account.account_type === 'savings' ? '저축' : '관리자'} 계좌
                </div>
                <div style={{ fontSize: 12, color: 'var(--gray-500)', fontFamily: 'monospace', marginTop: 2 }}>{account.account_number}</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontWeight: 700, color: 'var(--navy)', fontSize: 18 }}>{fmt(account.balance)}</div>
                <div style={{ fontSize: 11, color: 'var(--gray-500)', marginTop: 2 }}>계좌 ID: {account.id}</div>
              </div>
            </div>
          )}
        </div>
      )}


      {/* 최근 거래 */}
      {history.length > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 20 }}>최근 거래 내역</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>출금 계좌</th>
                  <th>입금 계좌</th>
                  <th>금액</th>
                  <th>내용</th>
                  <th>일시</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 10).map(t => (
                  <tr key={t.id}>
                    <td><span className="badge badge-gray">#{t.id}</span></td>
                    <td>{t.from_account_id}</td>
                    <td>{t.to_account_id}</td>
                    <td style={{ fontWeight: 600, color: 'var(--navy)' }}>{fmt(t.amount)}</td>
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
