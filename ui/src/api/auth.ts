// 管理 API token:仅保存在当前标签页会话,关页即清。

const TOKEN_KEY = 'edge-lb-token'

export class AuthError extends Error {
  constructor(message = 'missing or invalid bearer token') {
    super(message)
    this.name = 'AuthError'
  }
}

export function getToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? ''
}

export function setToken(token: string) {
  const value = token.trim()
  localStorage.removeItem(TOKEN_KEY)
  if (value) {
    sessionStorage.setItem(TOKEN_KEY, value)
  } else {
    sessionStorage.removeItem(TOKEN_KEY)
  }
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(TOKEN_KEY)
}
