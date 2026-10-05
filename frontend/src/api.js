// Every call to our own API goes through here, so authentication is handled in
// one place: the session cookie rides along automatically, and state-changing
// requests echo the CSRF token the server set in a readable cookie.

export class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

function readCookie(name) {
  const match = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

// FastAPI validation errors arrive as a list of {loc, msg}; show the messages.
function describe(data, status) {
  const detail = data?.detail ?? data?.error?.message;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg?.replace(/^Value error, /, '')).filter(Boolean).join(' ');
  }
  if (typeof detail === 'string') return detail;
  if (status === 429) return 'Too many requests. Wait a moment and try again.';
  if (status >= 500) return 'The server had a problem. Please try again.';
  return `Request failed (HTTP ${status})`;
}

async function request(method, path, body, { form = false, raw = false } = {}) {
  const headers = {};
  if (body !== undefined && !form) headers['Content-Type'] = 'application/json';
  if (!['GET', 'HEAD'].includes(method)) {
    const csrf = readCookie('rtg_csrf');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : form ? body : JSON.stringify(body),
  });

  // A lapsed session anywhere in the app sends the user back to sign in.
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    window.dispatchEvent(new Event('rtg:unauthorized'));
  }
  if (raw) return res;

  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) throw new ApiError(res.status, describe(data, res.status), data);
  return data;
}

export const api = {
  get: (path) => request('GET', path),
  post: (path, body = {}) => request('POST', path, body),
  put: (path, body = {}) => request('PUT', path, body),
  patch: (path, body = {}) => request('PATCH', path, body),
  del: (path, body) => request('DELETE', path, body),
  upload: (path, formData) => request('POST', path, formData, { form: true }),
  // For callers that need the status and body even on errors (the API sandbox).
  raw: (method, path, body) => request(method, path, body, { raw: true }),
};
