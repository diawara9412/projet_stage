import axios from 'axios';

export default function useApi() {
  const api = axios.create({ baseURL: process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api' });
  return api;
}
