export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// api authenticates with the signed HttpOnly session cookie the server
// set at login. The SPA never sees or stores a credential: there is no
// bearer token in JS-reachable storage for an XSS payload to steal.
export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...opts,
    credentials: "same-origin",
  });

  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new ApiError(res.status, body.error ?? res.statusText);
  }

  return body as T;
}

// login posts the username/password form to the same endpoint the
// server-rendered login page uses; on success the response chain sets
// the session cookie.
export async function login(username: string, password: string): Promise<void> {
  const body = new URLSearchParams({ username, password });
  const res = await fetch("/ui-login", {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!res.ok) {
    throw new ApiError(res.status, "invalid username or password");
  }
}

export async function logout(): Promise<void> {
  try {
    await api("/api/logout", { method: "POST" });
  } catch {
    // Clearing the cookie failed (already expired?); the reload below
    // lands on the login page either way.
  }
  window.location.assign("/");
}
