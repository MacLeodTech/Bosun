// The API client. Cookie sessions need the CSRF token on every state-changing request.

import type { Me } from './types';

let csrf: string | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

async function call<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['x-csrf-token'] = csrf;
  const r = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  });
  if (r.status === 204) return undefined as T;
  const text = await r.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!r.ok) {
    const err = data && typeof data === 'object' && 'error' in data ? String((data as { error: unknown }).error) : '';
    const msg = err || r.statusText || `HTTP ${r.status}`;
    if (r.status === 401) onUnauthorized();
    throw new ApiError(r.status, msg);
  }
  return data as T;
}

let unauthorizedHandler: () => void = () => {};
export function onUnauthorizedDo(f: () => void) {
  unauthorizedHandler = f;
}
function onUnauthorized() {
  unauthorizedHandler();
}

export const api = {
  get: <T>(p: string) => call<T>('GET', p),
  post: <T>(p: string, b?: unknown) => call<T>('POST', p, b ?? {}),
  put: <T>(p: string, b: unknown) => call<T>('PUT', p, b),
  patch: <T>(p: string, b: unknown) => call<T>('PATCH', p, b),
  del: <T>(p: string, b?: unknown) => call<T>('DELETE', p, b),
};

export async function login(username: string, password: string): Promise<Me> {
  const me = await api.post<Me>('/auth/login', { username, password });
  setCsrf(me.csrf);
  return me;
}

export async function setup(code: string, username: string, password: string): Promise<Me> {
  const me = await api.post<Me>('/setup', { code, username, password });
  setCsrf(me.csrf);
  return me;
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '' && v !== false) u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : '';
}
