import { app } from '../src/app';

describe('Health Check', () => {
  it('should return 200 OK', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: 'ok',
    });
  });
});

describe('Auth Endpoints', () => {
  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'testpassword123',
        name: 'Test User',
        role: 'USER',
      };

      const response = await app.inject({
        method: 'POST',
        url: '/api/auth/register',
        payload: userData,
      });

      expect(response.statusCode).toBe(201);
      expect(response.json()).toHaveProperty('user');
      expect(response.json()).toHaveProperty('token');
      expect(response.json().user.email).toBe(userData.email);
    });

    it('should not register user with invalid email', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'testpassword123',
        name: 'Test User',
      };

      const response = await app.inject({
        method: 'POST',
        url: '/api/auth/register',
        payload: userData,
      });

      expect(response.statusCode).toBe(400);
    });
  });
});

afterAll(async () => {
  await app.close();
});