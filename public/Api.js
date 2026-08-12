// api.js — Menghubungkan frontend ke backend
const API_URL = window.PORTOFOLIOVERSE_API_URL || 'http://localhost:5000/api';

let token = localStorage.getItem('token');

function apiRequest(endpoint, method = 'GET', data = null) {
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(`${API_URL}${endpoint}`, {
    method,
    headers,
    body: data ? JSON.stringify(data) : null,
  })
    .then(res => res.json())
    .catch(() => ({ error: 'Tidak bisa terhubung ke server. Cek koneksi atau apakah backend sedang jalan.' }));
}

// Auth
export const register = (name, email, phone, password) =>
  apiRequest('/auth/register', 'POST', { name, email, phone, password });
export const verify = (email, code) =>
  apiRequest('/auth/verify', 'POST', { email, code });
export const resendCode = (email) =>
  apiRequest('/auth/resend-code', 'POST', { email });
export const login = (email, password) =>
  apiRequest('/auth/login', 'POST', { email, password }).then(data => {
    if (data.token) {
      token = data.token;
      localStorage.setItem('token', token);
    }
    return data;
  });
export const forgot = (email) =>
  apiRequest('/auth/forgot', 'POST', { email });
export const reset = (email, code, newPassword) =>
  apiRequest('/auth/reset', 'POST', { email, code, newPassword });
export const logout = () => {
  token = null;
  localStorage.removeItem('token');
};

// Users
export const getMe = () => apiRequest('/users/me');
export const getUsers = () => apiRequest('/users');
export const getUser = (id) => apiRequest(`/users/${id}`);
export const updateMe = (data) => apiRequest('/users/me', 'PUT', data);
export const follow = (id) => apiRequest(`/users/follow/${id}`, 'POST');

// Posts
export const createPost = (content, media, links) =>
  apiRequest('/posts', 'POST', { content, media, links });
export const getFeed = () => apiRequest('/posts/feed');
export const getGlobal = () => apiRequest('/posts/global');
export const likePost = (postId) =>
  apiRequest(`/posts/${postId}/like`, 'POST');
export const commentPost = (postId, text) =>
  apiRequest(`/posts/${postId}/comment`, 'POST', { text });
export const sharePost = (postId) =>
  apiRequest(`/posts/${postId}/share`, 'POST');
export const deletePost = (postId) =>
  apiRequest(`/posts/${postId}`, 'DELETE');

// Messages
export const sendMessage = (toUserId, text) =>
  apiRequest('/messages', 'POST', { toUserId, text });
export const getMessages = (userId) =>
  apiRequest(`/messages/${userId}`);
export const getThreads = () => apiRequest('/messages/threads');

// Upload
export const uploadFile = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return fetch(`${API_URL}/upload`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData,
  })
    .then(res => res.json())
    .catch(() => ({ error: 'Upload gagal. Cek koneksi ke server.' }));
};