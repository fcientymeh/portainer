import { http, HttpResponse } from 'msw';

export const gitopsHandlers = [
  http.post('/api/gitops/repo/refs', () =>
    HttpResponse.json(['refs/heads/main', 'refs/heads/develop'])
  ),
  http.post('/api/gitops/repo/files/search', () =>
    HttpResponse.json(['docker-compose.yml'])
  ),
];
