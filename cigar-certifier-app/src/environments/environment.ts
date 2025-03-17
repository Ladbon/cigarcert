// src/environments/environment.ts
export const environment = {
  production: false,
  apiUrl: 'https://localhost:5001/api/auth'
};

export const publicEndpoints = [
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/request-password-reset',
  '/api/auth/reset-password',
];
