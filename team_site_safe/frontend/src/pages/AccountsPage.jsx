import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import { accountAPI, transferAPI } from '../utils/api';

function fmt(n) { return Number(n).toLocaleString('ko-KR') + '원'; }

export default function AccountsPage() {
  const [searchParams]  = useSearchParams();
  const navigate        = useNavigate();

  const [account,  setAccount]  = useState(null);   // 현재 조회 중인 계좌
  const [myId,     setMyId]     = useState(null);    // 내 계좌 ID
  const [history,  setHistory]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState('');

  const idParam = searchParams.get('id');            // URL ?id=

  // 1) 내 계좌 ID를 먼저 가져와서 URL에 세팅
  useEffect(() => {
    accountAPI.myAccounts().then(r => {
      const acc = r.data[0];
      if (!acc) return;
      setMyId(acc.id);
      // URL에 ?id= 없으면 내 계좌 ID로 자동 이동
      if (!searchParams.get('id')) {
        navigate(`/accounts?id=${acc.id}`, { replace: true });
      }
    }).catch(() => {});
  }, []);

  // 2) URL ?id= 가 바뀔 때마다 해당 계좌 + 거래 이력 조회 (IDOR)
  useEffect(() => {
    if (!idParam) return;
    setLoading(true); setError(''); setAccount(null); setHistory([]);

    accountAPI.getAccount(Number(idParam))
      .then(r => {
        setAccount(r.data);
        return transferAPI.history(r.data.id);
      })
      .then(r => setHistory(r.data))
      .catch(e => setError(e.response?.data?.detail || '계좌를 찾을 수 없습니다.'))
      .finally(() => setLoading(false));
  }, [idParam]);

  const isOwnAccount = myId !== null && account !== null && account.id === myId;

  return (
    <Layout>
      <div className="page-header">
        <h1 className="page-title">계좌 조회</h1>
      </div>

      {error && <div className="alert alert-error">⚠ {error}</div>}

      {/* 계좌 정보 카드 */}
      {loading ? (
        <div className="card" style={{ color: 'var(--gray-500)' }}>불러오는 중...</div>
      ) : account ? (
        <>
          <div
            className="balance-card"
            style={{ marginBottom: 28 }}
          >
            <div className="balance-label">계좌 잔액</div>
            <div className="balance-amount">{fmt(account.balance)}</div>
            <div style={{ display: 'flex', gap: 28, marginTop: 16, flexWrap: 'wrap' }}>
              {[
                ['계좌번호', account.account_number, true],
                ['계좌 ID',  `#${account.id}`,       false],
                ['소유자 ID',`#${account.user_id}`,  false],
                ['종류',      account.account_type,  false],
              ].map(([label, value, mono]) => (
                <div key={label}>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>{label}</div>
                  <div style={{
                    fontWeight: 600, color: 'var(--white)', marginTop: 2,
                    fontFamily: mono ? 'monospace' : 'inherit', fontSize: mono ? 13 : 14,
                  }}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 거래 이력 */}
          <div className="card">
            <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 20 }}>
              거래 내역
            </h3>

            {history.length === 0 ? (
              <p style={{ color: 'var(--gray-500)', fontSize: 14 }}>거래 내역이 없습니다.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>구분</th>
                      <th>상대 계좌</th>
                      <th>금액</th>
                      <th>내용</th>
                      <th>일시</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map(t => {
                      const isOut = t.from_account_id === account.id;
                      return (
                        <tr key={t.id}>
                          <td>
                            <span className={`badge ${isOut ? 'badge-red' : 'badge-green'}`}>
                              {isOut ? '출금' : '입금'}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: 13 }}>
                            #{isOut ? t.to_account_id : t.from_account_id}
                          </td>
                          <td style={{ fontWeight: 700, color: isOut ? 'var(--red)' : 'var(--green)' }}>
                            {isOut ? '-' : '+'}{fmt(t.amount)}
                          </td>
                          <td style={{ fontSize: 13 }}>{t.description || '-'}</td>
                          <td style={{ fontSize: 12, color: 'var(--gray-500)' }}>
                            {t.created_at?.substring(0, 16)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : null}
    </Layout>
  );
}
