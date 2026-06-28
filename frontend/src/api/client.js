import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

// ============================================================
// Analysis
// ============================================================

export const analyzeUpload = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/analyze/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  });
  return response.data;
};

export const analyzeHeaders = async (rawHeaders, bodyText = null, bodyHtml = null) => {
  const response = await api.post('/analyze/headers', {
    raw_headers: rawHeaders,
    body_text: bodyText,
    body_html: bodyHtml,
  });
  return response.data;
};

export const getAnalysis = async (caseId) => {
  const response = await api.get(`/analyze/${caseId}`);
  return response.data;
};

export const getAnalysisHistory = async (limit = 50) => {
  const response = await api.get('/analyze/history', { params: { limit } });
  return response.data;
};

// ============================================================
// Cases
// ============================================================

export const getCases = async (filters = {}) => {
  const response = await api.get('/cases', { params: filters });
  return response.data;
};

export const getCase = async (caseId) => {
  const response = await api.get(`/cases/${caseId}`);
  return response.data;
};

export const updateCase = async (caseId, data) => {
  const response = await api.patch(`/cases/${caseId}`, data);
  return response.data;
};

export const deleteCase = async (caseId) => {
  const response = await api.delete(`/cases/${caseId}`);
  return response.data;
};

// ============================================================
// Reports
// ============================================================

export const generateReport = async (caseId, format = 'pdf', analystName = null, notes = null) => {
  const response = await api.post('/reports/generate', {
    case_id: caseId,
    format,
    analyst_name: analystName,
    analyst_notes: notes,
  }, {
    responseType: format === 'json' ? 'json' : 'blob',
  });
  return response.data;
};

export const getReports = async () => {
  const response = await api.get('/reports');
  return response.data;
};

// ============================================================
// Threat Intelligence
// ============================================================

export const checkIOC = async (iocType, iocValue) => {
  const response = await api.post('/ioc/check', {
    ioc_type: iocType,
    ioc_value: iocValue,
  });
  return response.data;
};

export const bulkCheckIOCs = async (iocs) => {
  const response = await api.post('/ioc/bulk-check', { iocs });
  return response.data;
};

export const exportIOCs = async (caseId, format = 'csv') => {
  const response = await api.get(`/ioc/export/${caseId}`, {
    params: { format },
    responseType: format === 'csv' ? 'blob' : 'json',
  });
  return response.data;
};

// ============================================================
// Settings
// ============================================================

export const getSettings = async () => {
  const response = await api.get('/settings');
  return response.data;
};

export const updateSettings = async (data) => {
  const response = await api.patch('/settings', data);
  return response.data;
};

// ============================================================
// Health
// ============================================================

export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export default api;
