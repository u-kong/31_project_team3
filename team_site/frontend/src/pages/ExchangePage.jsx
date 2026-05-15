import React, { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { exchangeAPI } from '../utils/api';

export default function ExchangePage() {
  const [rates,   setRates]   = useState({});
  const [liveDate, setLiveDate] = useState('');
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  useEffect(() => {
    exchangeAPI.allRates().then(r => setRates(r.data)).catch(() => {});
  }, []);

  // 실시간 환율 조회 → 기존 rates에 덮어씀
  const handleLiveFetch = async () => {
    setLoading(true); setError('');
    try {
      const r = await exchangeAPI.liveRates();
      // 기존 change, change_pct는 유지하고 rate만 실제값으로 교체
      setRates(prev => {
        const updated = { ...prev };
        Object.entries(r.data.rates).forEach(([cur, data]) => {
          if (updated[cur]) {
            updated[cur] = { ...updated[cur], rate: data.rate };
          }
        });
        return updated;
      });
      setLiveDate(r.data.date);
    } catch (e) {
      setError(e.response?.data?.detail || '환율 데이터를 불러올 수 없습니다.');
    } finally {
      setLoading(false);
    }
  };

  const flagMap = { USD: '🇺🇸', EUR: '🇪🇺', JPY: '🇯🇵', CNY: '🇨🇳', GBP: '🇬🇧' };

  return (
    <Layout>
      <div className="page-header">
        <h1 className="page-title">환율 조회</h1>
        <p className="page-subtitle">KRW 기준 환율 정보를 확인합니다.</p>
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20 }}>
            현재 환율 (KRW 기준)
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {liveDate && (
              <span style={{ fontSize: 12, color: 'var(--gray-500)' }}>
                실시간 기준일: {liveDate} · ECB
              </span>
            )}
            <button
              className="btn btn-primary btn-sm"
              onClick={handleLiveFetch}
              disabled={loading}
            >
              {loading ? '조회 중...' : '실시간 환율 조회'}
            </button>
          </div>
        </div>

        {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>⚠ {error}</div>}

        <div className="rate-grid">
          {Object.entries(rates).map(([cur, data]) => (
            <div className="rate-card" key={cur}>
              <div style={{ fontSize: 22, marginBottom: 6 }}>{flagMap[cur]}</div>
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
    </Layout>
  );
}
