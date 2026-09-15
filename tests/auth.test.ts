import { createBarrierAuth, bearerToken, cookieToken, sessionCookie } from '../src/server/auth';

describe('barrier auth', () => {
  test('missing configuration denies access', () => {
    const auth = createBarrierAuth(undefined);
    expect(auth.enabled).toBe(false);
    expect(auth.verify(null)).toBe(false);
    expect(auth.verify('anything')).toBe(false);
  });

  test('enabled guard rejects missing/empty token', () => {
    const auth = createBarrierAuth('0123456789abcdef');
    expect(auth.enabled).toBe(true);
    expect(auth.verify(null)).toBe(false);
    expect(auth.verify('')).toBe(false);
    expect(auth.verify('wrong')).toBe(false);
  });

  test('enabled guard accepts exact match only', () => {
    const auth = createBarrierAuth('0123456789abcdef');
    expect(auth.verify('0123456789abcdef')).toBe(true);
    // Different length / close tokens must not match.
    expect(auth.verify('0123456789abcdef0')).toBe(false);
    expect(auth.verify('0123456789abcdefg')).toBe(false);
  });

  test('tokens shorter than 16 chars cannot open the control plane', () => {
    const auth = createBarrierAuth('short');
    expect(auth.enabled).toBe(false);
    expect(auth.verify('short')).toBe(false);
    expect(auth.verifyCookie('short')).toBe(false);
  });
});

describe('token extraction', () => {
  const mkReq = (headers: Record<string, string>) =>
    ({ headers }) as unknown as Parameters<typeof bearerToken>[0];

  test('bearerToken parses Authorization header', () => {
    expect(bearerToken(mkReq({ authorization: 'Bearer abc123' }))).toBe('abc123');
    expect(bearerToken(mkReq({ authorization: 'bearer abc def' }))).toBe('abc def');
    expect(bearerToken(mkReq({ authorization: 'Basic x' }))).toBe(null);
    expect(bearerToken(mkReq({}))).toBe(null);
  });

  test('cookieToken parses operator cookie', () => {
    expect(cookieToken(mkReq({ cookie: 'vaivar_operator=abc' }))).toBe('abc');
    expect(cookieToken(mkReq({ cookie: 'a=1; vaivar_operator=tok; b=2' }))).toBe('tok');
    expect(cookieToken(mkReq({}))).toBe(null);
  });

  test('cookieToken prefers admin session cookie', () => {
    expect(cookieToken(mkReq({ cookie: 'vaivar_admin=adm; vaivar_operator=op' }))).toBe('adm');
    expect(sessionCookie(mkReq({ cookie: 'vaivar_admin=adm; vaivar_operator=op' }))).toEqual({
      name: 'vaivar_admin',
      value: 'adm',
    });
    expect(sessionCookie(mkReq({ cookie: 'vaivar_operator=op' }))).toEqual({
      name: 'vaivar_operator',
      value: 'op',
    });
  });
});
