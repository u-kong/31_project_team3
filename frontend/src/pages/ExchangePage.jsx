import React, { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { exchangeAPI } from '../utils/api';

export default function ExchangePage() {
  const [rates,  setRates]  = useState({});
  const [ssrfUrl, setSsrfUrl] = useState('');
  const [ssrfRes, setSsrfRes] = useState('');
  const [error,  setError]  = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    exchangeAPI.allRates().then(r => setRates(r.data)).catch(() => {});
  }, []);

  // [VULN] SSRF: url 파라미터를 서버가 그대로 fetch
  const handleSsrf = async () => {
    setError(''); setSsrfRes(''); setLoading(true);
    try {
      const r = await exchangeAPI.ssrfFetch(ssrfUrl);
      setSsrfRes(JSON.stringify(r.data, null, 2));
    } catch (e) {
      setError(e.response?.data?.detail || '요청 실패');
    } finally { setLoading(false); }
  };

  const flagColors = { USD: '🇺🇸', EUR: '🇪🇺', JPY: '🇯🇵', CNY: '🇨🇳', GBP: '🇬🇧' };

  return (
    <Layout>
      <div className="page-header">
        <h1 className="page-title">환율 조회</h1>
        <p className="page-subtitle">실시간 환율 정보와 외부 데이터를 조회합니다.</p>
      </div>

      {/* 환율 카드 */}
      <div className="card" style={{ marginBottom: 28 }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 20 }}>현재 환율 (KRW 기준)</h3>
        <div className="rate-grid">
          {Object.entries(rates).map(([cur, data]) => (
            <div className="rate-card" key={cur}>
              <div style={{ fontSize: 22, marginBottom: 6 }}>{flagColors[cur]}</div>
              <div className="rate-currency">{cur}</div>
              <div className="rate-value" style={{ color: 'var(--navy)' }}>
                ₩{Number(data.rate).toLocaleString('ko-KR', { minimumFractionDigits: 2 })}
              </div>
              <div className={`rate-change ${data.change >= 0 ? 'up' : 'down'}`}>
                {data.change >= 0 ? '▲' : '▼'} {Math.abs(data.change)} ({data.change_pct > 0 ? '+' : ''}{data.change_pct}%)
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SSRF 패널 */}
      <div className="card" style={{ border: '1.5px solid rgba(239,68,68,0.2)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20 }}>외부 환율 데이터 조회</h3>
          <span className="badge badge-red">SSRF</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--gray-500)', marginBottom: 20 }}>
          외부 API URL을 직접 입력하면 서버가 해당 URL로 요청을 전송합니다.
        </p>

        <div style={{ background: 'rgba(59,130,246,0.06)', borderRadius: 8, padding: '12px 16px', marginBottom: 20, fontSize: 12, color: '#2563eb' }}>
          <strong>테스트 URL 예시:</strong><br />
          • https://httpbin.org/json<br />
          • http://169.254.169.254/latest/meta-data/ (AWS 메타데이터)<br />
          • http://localhost:8000/admin/users (내부 서비스)
        </div>

        {error && <div className="alert alert-error">⚠ {error}</div>}

        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <input
            className="form-input"
            placeholder="https://example.com/api/rates"
            value={ssrfUrl}
            onChange={e => setSsrfUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSsrf()}
          />
          <button className="btn btn-danger" onClick={handleSsrf} disabled={loading} style={{ whiteSpace: 'nowrap' }}>
            {loading ? '요청 중...' : '요청 전송'}
          </button>
        </div>

        {ssrfRes && (
          <div>
            <div style={{ fontSize: 12, color: 'var(--gray-500)', marginBottom: 8 }}>응답 결과:</div>
            <pre style={{
              background: 'var(--navy)',
              color: 'var(--gold-light)',
              padding: '16px',
              borderRadius: 8,
              fontSize: 12,
              fontFamily: 'monospace',
              overflowX: 'auto',
              maxHeight: 300,
              lineHeight: 1.6,
            }}>
              {ssrfRes}
            </pre>
          </div>
        )}
      </div>
    </Layout>
  );
}
