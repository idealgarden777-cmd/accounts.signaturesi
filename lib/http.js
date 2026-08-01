export function setJsonHeaders(res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
}

export function parseJsonBody(req) {
  if (typeof req.body === 'object' && req.body !== null) {
    return req.body;
  }
  try {
    return JSON.parse(req.body);
  } catch {
    return null;
  }
}

export function isAllowedOrigin(req) {
  const origin = req.headers.origin || req.headers.referer || '';
  if (!origin) return true; // Server-to-server / Same-origin
  return origin.includes('signaturesi.com') || origin.includes('vercel.app') || origin.includes('localhost');
}
