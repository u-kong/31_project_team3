import React, { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { accountAPI, transferAPI } from '../utils/api';

function fmt(n) { return Number(n).toLocaleString('ko-KR') + '원'; }

function getTokenRole() {
  try {
    const token = localStorage.getItem('token') || '';
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.role || 'user';
  } catch { return 'user'; }
}

export default function TransferPage() {
  const [accounts, setAccounts] = useState([]);
  const [form, setForm]         = useState({
    from_account_id: '',
    to_account_id: '',
    amount: '',
    description: '',
    transfer_pin: '',   // [PATCH] 이체 비밀번호 추가
  });
  const [adminForm, setAdminForm] = useState({ from_account_id: '', to_account_id: '', amount: '', description: '' });
  const [msg, setMsg]           = useState({ type: '', text: '' });
  const [adminMsg, setAdminMsg] = useState({ type: '', text: '' });

  const tokenRole = getTokenRole();
  const isAdmin = tokenRole === 'admin';

  useEffect(() => {
    accountAPI.myAccounts().then(r => setAccounts(r.data)).catch(() => {});
  }, []);

  const change = (setter) => e => setter(prev => ({ ...prev, [e.target.name]: e.target.value }));

  const handleTransfer = async () => {
    setMsg({ type: '', text: '' });

    // [PATCH] 이체 비밀번호 클라이언트 검증
    if (!form.transfer_pin) {
      setMsg({ type: 'error', text: '이체 비밀번호를 입력해주세요.' });
      return;
    }

    try {
      await transferAPI.transfer({
        from_account_id: Number(form.from_account_id),
        to_account_id:   Number(form.to_account_id),
        amount:          Number(form.amount),
        description:     form.description,
        transfer_pin:    form.transfer_pin,   // [PATCH] 서버에 PIN 전송
      });
      setMsg({ type: 'success', text: '이체가 완료되었습니다.' });
      setForm(prev => ({ ...prev, transfer_pin: '' }));  // PIN 초기화
    } catch (e) {
      setMsg({ type: 'error', text: e.response?.data?.detail || '이체 실패' });
    }
  };

  const handleAdminForce = async () => {
    setAdminMsg({ type: '', text: '' });
    try {
      await transferAPI.adminForce({
        from_account_id: Number(adminForm.from_account_id),
        to_account_id:   Number(adminForm.to_account_id),
        amount:          Number(adminForm.amount),
        description:     adminForm.description,
      });
      setAdminMsg({ type: 'success', text: '[Admin] 강제 이체 완료' });
    } catch (e) {
      setAdminMsg({ type: 'error', text: e.response?.data?.detail || '실패' });
    }
  };

  return (
    <Layout>
      <div className="page-header">
        <h1 className="page-title">계좌 이체</h1>
        <p className="page-subtitle">계좌 간 자금을 이체합니다.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: isAdmin ? '1fr 1fr' : '1fr', gap: 24, marginBottom: 24 }}>
        {/* 일반 이체 */}
        <div className="card">
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20, marginBottom: 6 }}>일반 이체</h3>
          {msg.text && <div className={`alert alert-${msg.type === 'error' ? 'error' : 'success'}`}>{msg.text}</div>}
          {[
            ['from_account_id', '출금 계좌 ID', '예: 1, 2, 3'],
            ['to_account_id',   '입금 계좌 ID', '예: 1, 2, 3'],
            ['amount',          '금액 (원)',    '예: 100000'],
            ['description',     '내용',         '이체 메모'],
          ].map(([name, label, ph]) => (
            <div className="form-group" key={name}>
              <label className="form-label">{label}</label>
              <input className="form-input" name={name} placeholder={ph}
                value={form[name]} onChange={change(setForm)} />
            </div>
          ))}

          {/* [PATCH] 이체 비밀번호 입력 */}
          <div className="form-group">
            <label className="form-label">이체 비밀번호</label>
            <input
              className="form-input"
              name="transfer_pin"
              type="password"
              placeholder="이체 비밀번호 입력"
              value={form.transfer_pin}
              onChange={change(setForm)}
            />
          </div>

          <button className="btn btn-gold btn-full" onClick={handleTransfer}>이체하기</button>
        </div>

        {/* 관리자 강제 이체 */}
        {isAdmin && (
        <div className="card" style={{ border: '1.5px solid rgba(239,68,68,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 20 }}>관리자 강제 이체</h3>
            <span className="badge badge-red">ADMIN</span>
          </div>
          {adminMsg.text && <div className={`alert alert-${adminMsg.type === 'error' ? 'error' : 'success'}`}>{adminMsg.text}</div>}
          {[
            ['from_account_id', '출금 계좌 ID', '강제 출금 계좌'],
            ['to_account_id',   '입금 계좌 ID', '강제 입금 계좌'],
            ['amount',          '금액 (원)',    '임의 금액'],
          ].map(([name, label, ph]) => (
            <div className="form-group" key={name}>
              <label className="form-label">{label}</label>
              <input className="form-input" name={name} placeholder={ph}
                value={adminForm[name]} onChange={change(setAdminForm)} />
            </div>
          ))}
          <button className="btn btn-danger btn-full" onClick={handleAdminForce}>강제 이체 실행</button>
        </div>
        )}
      </div>
    </Layout>
  );
}
