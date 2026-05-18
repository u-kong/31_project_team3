import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: API_URL });

// [VULN] JWT를 localStorage에 저장 (XSS 취약)
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token');
  if (token) cfg.headers['Authorization'] = `Bearer ${token}`;
  return cfg;
});

export const authAPI = {
  login:    (data) => api.post('/auth/login', data),
  register: (data) => api.post('/auth/register', data),
};

export const accountAPI = {
  myAccounts:    ()     => api.get('/accounts/my'),
  getAccount:    (id)   => api.get(`/accounts?id=${id}`),      // IDOR
  searchAccount: (q)    => api.get(`/accounts/search?q=${q}`), // SQLi
};

export const transferAPI = {
  transfer:      (data) => api.post('/transfer', data),
  adminForce:    (data) => api.post('/transfer/admin/force', data), // BAC
  history:       (id)   => api.get(`/transfer/history?account_id=${id}`), // IDOR
};

export const exchangeAPI = {
  allRates:  ()    => api.get('/exchange/rates'),
  rate:      (cur) => api.get(`/exchange/rate?currency=${cur}`),
  liveRates: ()    => api.get('/exchange/rates/live'),
  ssrfFetch: (url) => api.get(`/exchange/rate?url=${encodeURIComponent(url)}`),
};

export const adminAPI = {
  users:        () => api.get('/admin/users'),        // BAC
  accounts:     () => api.get('/admin/accounts'),     // BAC
  transactions: () => api.get('/admin/transactions'), // BAC
  deleteUser:   (id) => api.delete(`/admin/users/${id}`),
};

export default api;
