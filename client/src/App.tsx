// src/App.tsx
import { h } from 'preact';
import { useMemo, useState } from 'preact/hooks';
import { ApiClient } from './api/ApiClient';
import { MSCHAPCrypto } from './crypto/MSCHAPCrypto';
import { ProtocolDemoService, ILogger } from './services/MSCHAPService.ts';

export function App() {
  const [username, setUsername] = useState('User');
  const [password, setPassword] = useState('P@ssw0rd');
  const [log, setLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<null | boolean>(null);

  // отдельный клиент для протокола (аутентификация)
  const protocolService = useMemo(() => {
    const api = new ApiClient('/api');
    const crypto = new MSCHAPCrypto();
    return new ProtocolDemoService(api, crypto);
  }, []);

  // отдельный клиент для регистрации (можно было переиспользовать, но так понятнее архитектурно)
  const apiClient = useMemo(() => new ApiClient('/api'), []);

  const logger: ILogger = {
    log: (message: string) => {
      setLog(prev => [...prev, message]);
    },
  };

  async function handleRunDemo() {
    setLoading(true);
    setResult(null);
    setLog([]);

    try {
      const success = await protocolService.runDemo(username, password, logger);
      setResult(success);
    } catch (e: any) {
      logger.log(`✗ Ошибка: ${e?.message ?? String(e)}`);
      setResult(false);
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister() {
    setLoading(true);
    setResult(null);
    setLog([]);

    try {
      logger.log(`→ Регистрация пользователя "${username}"...`);
      const res = await apiClient.register(username, password);
      if (res.success) {
        logger.log('Пользователь успешно зарегистрирован');
      } else {
        logger.log('Регистрация неуспешна (success = false)');
      }
    } catch (e: any) {
      logger.log(`Ошибка регистрации: ${e?.message ?? String(e)}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0f172a',
      color: '#e5e7eb',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '900px',
        background: '#020617',
        borderRadius: '1.5rem',
        padding: '1.5rem',
        boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
        border: '1px solid #1e293b',
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1.8fr)',
        gap: '1.5rem'
      }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', marginBottom: '0.75rem' }}>MS-CHAPv2 Demo</h1>
          <p style={{ fontSize: '0.9rem', color: '#9ca3af', marginBottom: '1.5rem' }}>
            Клиент считает NT-Response в браузере и отправляет его на сервер через nginx-прокси.
          </p>

          <label style={{ display: 'block', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#9ca3af' }}>Username</span>
            <input
              value={username}
              onInput={(e: any) => setUsername(e.currentTarget.value)}
              style={{
                width: '100%',
                marginTop: '0.25rem',
                padding: '0.5rem 0.75rem',
                borderRadius: '0.75rem',
                border: '1px solid #1f2937',
                background: '#020617',
                color: '#e5e7eb',
                outline: 'none'
              }}
            />
          </label>

          <label style={{ display: 'block', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#9ca3af' }}>Password</span>
            <input
              type="password"
              value={password}
              onInput={(e: any) => setPassword(e.currentTarget.value)}
              style={{
                width: '100%',
                marginTop: '0.25rem',
                padding: '0.5rem 0.75rem',
                borderRadius: '0.75rem',
                border: '1px solid #1f2937',
                background: '#020617',
                color: '#e5e7eb',
                outline: 'none'
              }}
            />
          </label>

                    <button
            onClick={handleRunDemo}
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.6rem 1rem',
              borderRadius: '999px',
              border: 'none',
              cursor: loading ? 'default' : 'pointer',
              fontWeight: 600,
              background: loading ? '#334155' : '#22c55e',
              color: '#020617',
              transition: 'background 0.15s, transform 0.1s'
            }}
          >
            {loading ? 'Выполняем handshake...' : 'Запустить демонстрацию MS-CHAPv2'}
          </button>

          <button
            onClick={handleRegister}
            disabled={loading}
            style={{
              width: '100%',
              marginTop: '0.5rem',
              padding: '0.5rem 1rem',
              borderRadius: '999px',
              border: '1px solid #4b5563',
              cursor: loading ? 'default' : 'pointer',
              fontWeight: 500,
              background: '#020617',
              color: '#e5e7eb',
              transition: 'background 0.15s, transform 0.1s'
            }}
          >
            {loading ? 'Регистрация...' : 'Зарегистрировать пользователя'}
          </button>


          {result !== null && (
            <div style={{ marginTop: '1rem', fontSize: '0.9rem' }}>
              {result
                ? <span style={{ color: '#4ade80' }}>Аутентификация успешна</span>
                : <span style={{ color: '#f97373' }}>Аутентификация провалена</span>
              }
            </div>
          )}
        </div>

        <div style={{
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          fontSize: '0.75rem',
          background: '#020617',
          borderRadius: '1rem',
          border: '1px solid #1f2937',
          padding: '0.75rem',
          overflow: 'auto',
          maxHeight: '420px'
        }}>
          <div style={{ color: '#9ca3af', marginBottom: '0.5rem' }}>Лог шагов:</div>
          {log.length === 0 && (
            <div style={{ color: '#4b5563' }}>Нажми кнопку, чтобы увидеть ход протокола.</div>
          )}
          {log.map((line, idx) => (
            <div key={idx} style={{ marginBottom: '0.25rem' }}>
              {line}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
