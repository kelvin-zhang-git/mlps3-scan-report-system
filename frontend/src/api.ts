export type User = {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  theme_preference: string;
  is_active?: boolean;
};

const TOKEN = "mlps_token";

export function token() {
  return localStorage.getItem(TOKEN) || "";
}

export function saveSession(accessToken: string, user: User) {
  localStorage.setItem(TOKEN, accessToken);
  localStorage.setItem("mlps_user", JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(TOKEN);
  localStorage.removeItem("mlps_user");
}

export function savedUser(): User | null {
  const raw = localStorage.getItem("mlps_user");
  return raw ? (JSON.parse(raw) as User) : null;
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData) && !headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token()) headers.set("Authorization", `Bearer ${token()}`);
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      /* 非 JSON 错误保持状态文本 */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return response.json();
  return response as T;
}

export async function download(path: string, filename: string) {
  const response = await fetch(path, { headers: { Authorization: `Bearer ${token()}` } });
  if (!response.ok) throw new Error("下载失败");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
