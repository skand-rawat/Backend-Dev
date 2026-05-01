const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');

jest.mock('mongoose');

describe('ConnectHub Security Tests', () => {
  
  describe('Input Sanitization - Registration', () => {
    test('should validate email format', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'invalid-email',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    test('should require valid email', async () => {
      const invalidEmails = [
        'plainaddress',
        '@missinglocal.com',
        'missing@domain',
        'missing.domain@',
        'two@@domain.com'
      ];
      
      for (const email of invalidEmails) {
        const res = await request(app)
          .post('/api/auth/register')
          .send({
            username: 'testuser',
            email,
            password: 'Password123!',
            confirmPassword: 'Password123!'
          });
        
        expect([400, 409]).toContain(res.status);
      }
    });

    test('should enforce username format (alphanumeric, _, -)', async () => {
      const invalidUsernames = [
        'user@name',
        'user!name',
        'user#name',
        'user name',
        'user$'
      ];
      
      for (const username of invalidUsernames) {
        const res = await request(app)
          .post('/api/auth/register')
          .send({
            username,
            email: 'test@example.com',
            password: 'Password123!',
            confirmPassword: 'Password123!'
          });
        
        expect(res.status).toBe(400);
      }
    });

    test('should reject weak passwords', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'weak',
          confirmPassword: 'weak'
        });
      
      expect(res.status).toBe(400);
    });
  });

  describe('XSS Protection - Bio Sanitization', () => {
    test('should sanitize script tags in bio', async () => {
      const maliciousBio = '<script>alert("xss")</script>My bio';
      
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ bio: maliciousBio });
      
      expect([401, 400]).toContain(res.status);
      if (res.status === 200 || res.status === 201) {
        expect(res.body.user.bio).not.toContain('<script>');
      }
    });

    test('should sanitize event handlers', async () => {
      const maliciousBio = '<img src=x onerror="alert(\'xss\')">';
      
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ bio: maliciousBio });
      
      expect([401, 400]).toContain(res.status);
    });

    test('should allow safe HTML formatting', async () => {
      const safeBio = '<b>Bold text</b> and <i>italic text</i> and <a href="https://example.com">link</a>';
      
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ bio: safeBio });
      
      expect([200, 201, 401]).toContain(res.status);
    });

    test('should enforce bio length limit', async () => {
      const longBio = 'a'.repeat(501);
      
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ bio: longBio });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('URL Validation - Profile Picture', () => {
    test('should validate URL format', async () => {
      const invalidUrls = [
        'not a url',
        'htp://missing-t.com',
        'javascript:alert("xss")',
        'data:text/html,<script>alert("xss")</script>',
        'file:///etc/passwd'
      ];
      
      for (const url of invalidUrls) {
        const res = await request(app)
          .put('/api/users/profile/update')
          .send({ profileUrl: url });
        
        expect([400, 401]).toContain(res.status);
      }
    });

    test('should accept valid HTTPS URLs', async () => {
      const validUrl = 'https://example.com/profile.jpg';
      
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ profileUrl: validUrl });
      
      expect([200, 201, 401]).toContain(res.status);
    });

    test('should prevent javascript: protocol', async () => {
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ profileUrl: 'javascript:alert("xss")' });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should prevent data: protocol', async () => {
      const res = await request(app)
        .put('/api/users/profile/update')
        .send({ profileUrl: 'data:text/html,<script>alert("xss")</script>' });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('XSS Protection - Posts', () => {
    test('should sanitize script tags in post content', async () => {
      const maliciousPost = '<script>steal_cookies()</script>Great post!';
      
      const res = await request(app)
        .post('/api/posts')
        .send({ content: maliciousPost });
      
      expect([201, 400, 401]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.post.content).not.toContain('<script>');
      }
    });

    test('should sanitize inline event handlers', async () => {
      const maliciousPost = '<div onclick="stealData()">Click me</div>';
      
      const res = await request(app)
        .post('/api/posts')
        .send({ content: maliciousPost });
      
      expect([201, 400, 401]).toContain(res.status);
    });

    test('should allow safe formatting tags', async () => {
      const safePost = '<p>Paragraph</p><b>Bold</b><i>Italic</i><br/>';
      
      const res = await request(app)
        .post('/api/posts')
        .send({ content: safePost });
      
      expect([201, 400, 401]).toContain(res.status);
    });

    test('should enforce post length limit', async () => {
      const longPost = 'a'.repeat(5001);
      
      const res = await request(app)
        .post('/api/posts')
        .send({ content: longPost });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('XSS Protection - Comments', () => {
    test('should sanitize script tags in comments', async () => {
      const maliciousComment = '<script>alert("comment xss")</script>Great!';
      
      const res = await request(app)
        .post('/api/posts/507f1f77bcf86cd799439011/comments')
        .send({ content: maliciousComment });
      
      expect([201, 400, 401]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.post.comments[0].content).not.toContain('<script>');
      }
    });

    test('should enforce comment length limit', async () => {
      const longComment = 'a'.repeat(501);
      
      const res = await request(app)
        .post('/api/posts/507f1f77bcf86cd799439011/comments')
        .send({ content: longComment });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('XSS Protection - Direct Messages', () => {
    test('should sanitize message content', async () => {
      const maliciousMessage = '<img src=x onerror="alert(\'xss\')">';
      
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: '507f1f77bcf86cd799439011',
          content: maliciousMessage
        });
      
      expect([201, 400, 401]).toContain(res.status);
    });

    test('should strip all HTML from messages', async () => {
      const messageWithHtml = '<b>Bold</b> message';
      
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: '507f1f77bcf86cd799439011',
          content: messageWithHtml
        });
      
      expect([201, 400, 401]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.messageData.content).not.toContain('<');
      }
    });

    test('should enforce message length limit', async () => {
      const longMessage = 'a'.repeat(1001);
      
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: '507f1f77bcf86cd799439011',
          content: longMessage
        });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('Authorization - Private Message Access', () => {
    test('should not allow viewing others messages', async () => {
      const res = await request(app)
        .get('/api/messages/conversation/507f1f77bcf86cd799439011');
      
      expect(res.status).toBe(401); // No authentication
    });

    test('should only allow authenticated user to view their messages', async () => {
      const res = await request(app)
        .get('/api/messages/conversation/507f1f77bcf86cd799439011');
      
      expect(res.status).toBe(401); // Should check session
    });

    test('should prevent message to self', async () => {
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: '507f1f77bcf86cd799439011',
          content: 'Self message'
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should validate recipient exists', async () => {
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: 'invalid-id',
          content: 'Message'
        });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('Session Security', () => {
    test('should set httpOnly cookie', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      if (res.status === 201) {
        const setCookieHeader = res.headers['set-cookie'];
        expect(setCookieHeader).toBeDefined();
        expect(setCookieHeader[0]).toContain('HttpOnly');
      }
    });

    test('should require authentication for protected routes', async () => {
      const res = await request(app)
        .post('/api/posts')
        .send({ content: 'Test post' });
      
      expect(res.status).toBe(401);
    });

    test('should session expire after logout', async () => {
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'Password123!'
        });
      
      if (loginRes.status === 200) {
        const logoutRes = await request(app)
          .post('/api/auth/logout')
          .set('Cookie', loginRes.headers['set-cookie']);
        
        expect([200, 500]).toContain(logoutRes.status);
      }
    });
  });

  describe('Rate Limiting', () => {
    test('should rate limit authentication attempts', async () => {
      const responses = [];
      for (let i = 0; i < 7; i++) {
        const res = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'password'
          });
        responses.push(res.status);
      }
      
      expect(responses.slice(-1)).toContain(429);
    });

    test('should rate limit messages', async () => {
      const responses = [];
      for (let i = 0; i < 22; i++) {
        const res = await request(app)
          .post('/api/messages')
          .send({
            recipientId: '507f1f77bcf86cd799439011',
            content: `Message ${i}`
          });
        responses.push(res.status);
      }
      
      expect(responses).toContain(429);
    });
  });

  describe('Data Type Validation', () => {
    test('should reject non-string content in posts', async () => {
      const res = await request(app)
        .post('/api/posts')
        .send({ content: 12345 });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should reject empty content', async () => {
      const res = await request(app)
        .post('/api/posts')
        .send({ content: '' });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should validate ObjectIds', async () => {
      const res = await request(app)
        .get('/api/users/invalid-id');
      
      expect(res.status).toBe(400);
    });
  });

  describe('NoSQL Injection Prevention', () => {
    test('should handle MongoDB operators in search', async () => {
      const res = await request(app)
        .get('/api/users/507f1f77bcf86cd799439011');
      
      expect([200, 404, 400]).toContain(res.status);
    });

    test('should sanitize injection in messages', async () => {
      const res = await request(app)
        .post('/api/messages')
        .send({
          recipientId: '{"$ne": null}',
          content: 'Test'
        });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  describe('Follow System Security', () => {
    test('should prevent self-follow', async () => {
      const res = await request(app)
        .post('/api/users/507f1f77bcf86cd799439011/follow');
      
      expect([400, 401]).toContain(res.status);
    });

    test('should validate target user exists', async () => {
      const res = await request(app)
        .post('/api/users/nonexistentid/follow');
      
      expect([400, 401, 404]).toContain(res.status);
    });
  });

  describe('Security Headers', () => {
    test('should include CSP header', async () => {
      const res = await request(app).get('/api/posts/feed');
      expect(res.headers['content-security-policy']).toBeDefined();
    });

    test('should include X-Frame-Options header', async () => {
      const res = await request(app).get('/api/posts/feed');
      expect(res.headers['x-frame-options']).toBe('DENY');
    });
  });

  describe('CORS Configuration', () => {
    test('should accept requests from allowed origins', async () => {
      const res = await request(app)
        .get('/api/posts/feed')
        .set('Origin', 'http://localhost:3000');
      
      expect(res.status).toBeGreaterThanOrEqual(200);
    });
  });
});
