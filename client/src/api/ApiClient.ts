// src/api/ApiClient.ts

export interface ChallengeResponseDto {
  session_id: string;
  auth_challenge: string; // base64
}

export interface AuthResultDto {
  success: boolean;
  server_nt_response: string; // base64
}


export interface RegisterResultDto {
  success: boolean;
}

export class ApiClient {
  constructor(private readonly baseUrl: string = '/api') {}

  public async getChallenge(username: string): Promise<ChallengeResponseDto> {
    const res = await fetch(`${this.baseUrl}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });

    if (!res.ok) {
      throw new Error(`Challenge request failed: ${res.status}`);
    }

    return res.json();
  }

  public async sendAuthResponse(params: {
    sessionId: string;
    username: string;
    peerChallengeB64: string;
    ntResponseB64: string;
  }): Promise<AuthResultDto> {
    const res = await fetch(`${this.baseUrl}/auth/response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: params.sessionId,
        username: params.username,
        peer_challenge: params.peerChallengeB64,
        nt_response: params.ntResponseB64,
      }),
    });

    if (!res.ok) {
      throw new Error(`Auth response failed: ${res.status}`);
    }

    return res.json();
  }

  public async register(username: string, password: string): Promise<RegisterResultDto> {
    const res = await fetch(`${this.baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      if (res.status === 400) {
        const data = await res.json().catch(() => null);
        const detail = (data as any)?.detail ?? 'Bad request';
        throw new Error(`Registration failed: ${detail}`);
      }
      throw new Error(`Registration failed: ${res.status}`);
    }

    return res.json();
  }
}
