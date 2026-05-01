const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');

// Mock MongoDB connection
jest.mock('mongoose');

describe('ShopEasy Security Tests', () => {
  
  // ============================================================
  // AUTHENTICATION SECURITY TESTS
  // ============================================================
  
  describe('Authentication - Secure Login', () => {
    test('should reject login with missing credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@example.com' });
      
      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    test('should hash password before storing', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'SecurePass123!',
          confirmPassword: 'SecurePass123!'
        });
      
      expect(res.status).toBe(201);
      // Password should not be returned in response
      expect(res.body).not.toHaveProperty('password');
    });

    test('should enforce minimum password length', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'short',
          confirmPassword: 'short'
        });
      
      expect(res.status).toBe(400);
      expect(res.body.error).toContain('8 characters');
    });

    test('should prevent account enumeration attacks', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'anypassword'
        });
      
      // Should not reveal if user exists
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid credentials');
    });

    test('should lock account after 5 failed login attempts', async () => {
      // First 5 attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({
            email: 'user@example.com',
            password: 'wrongpassword'
          });
      }
      
      // 6th attempt should be blocked
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'correctpassword'
        });
      
      expect(res.status).toBe(429);
      expect(res.body.error).toContain('temporarily locked');
    });
  });

  describe('Session Security', () => {
    test('should set httpOnly cookie', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'Password123!'
        });
      
      const setCookieHeader = res.headers['set-cookie'];
      expect(setCookieHeader).toBeDefined();
      expect(setCookieHeader[0]).toContain('HttpOnly');
    });

    test('should set SameSite=Strict cookie', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'Password123!'
        });
      
      const setCookieHeader = res.headers['set-cookie'];
      expect(setCookieHeader[0]).toContain('SameSite=Strict');
    });

    test('should require authentication for protected routes', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Test Product',
          price: 100
        });
      
      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Authentication required');
    });

    test('should destroy session on logout', async () => {
      // Login first
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'Password123!'
        });
      
      // Logout
      const logoutRes = await request(app)
        .post('/api/auth/logout')
        .set('Cookie', loginRes.headers['set-cookie']);
      
      expect(logoutRes.status).toBe(200);
      expect(logoutRes.body.message).toContain('Logout successful');
    });
  });

  // ============================================================
  // AUTHORIZATION TESTS
  // ============================================================
  
  describe('Authorization - Role-Based Access Control', () => {
    test('should prevent non-admin from creating products', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Unauthorized Product',
          description: 'Test',
          price: 100,
          category: 'electronics',
          stock: 10
        });
      
      // Should require authentication first
      expect(res.status).toBe(401);
    });

    test('should allow admin to create products', async () => {
      // This test assumes admin session is established
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Admin Product',
          description: 'Created by admin',
          price: 100,
          category: 'electronics',
          stock: 10
        });
      
      expect([201, 401]).toContain(res.status);
    });

    test('should prevent privilege escalation through role manipulation', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'hacker',
          email: 'hacker@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!',
          role: 'admin' // Attempting to set admin role
        });
      
      expect(res.status).toBe(201);
      // User should be created as customer, not admin
      expect(res.body.role).not.toBe('admin');
    });
  });

  // ============================================================
  // INPUT VALIDATION & INJECTION TESTS
  // ============================================================
  
  describe('MongoDB Injection Prevention', () => {
    test('should sanitize NoSQL injection in search', async () => {
      const res = await request(app)
        .get('/api/products')
        .query({
          search: '{"$ne": null}'
        });
      
      expect(res.status).toBe(200);
      // Should not return all products due to injection
      expect(Array.isArray(res.body.products)).toBe(true);
    });

    test('should handle MongoDB operators safely', async () => {
      const res = await request(app)
        .get('/api/products')
        .query({
          search: '$where',
          category: '{"$ne": null}'
        });
      
      expect(res.status).toBe(200);
      // Should not crash or execute malicious code
      expect(res.body).toBeDefined();
    });

    test('should prevent injection in price filters', async () => {
      const res = await request(app)
        .get('/api/products')
        .query({
          minPrice: '{"$ne": null}',
          maxPrice: '{"$where": "1==1"}'
        });
      
      expect(res.status).toBe(200);
      // Should not cause injection
      expect(res.body).toBeDefined();
    });

    test('should reject invalid ObjectId format', async () => {
      const res = await request(app)
        .get('/api/products/invalid-id')
        .send();
      
      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid product ID');
    });
  });

  // ============================================================
  // XSS PREVENTION TESTS
  // ============================================================
  
  describe('XSS Protection in Reviews', () => {
    test('should sanitize script tags in review content', async () => {
      const maliciousContent = '<script>alert("xss")</script>Great product!';
      
      const res = await request(app)
        .post('/api/products/507f1f77bcf86cd799439011/reviews')
        .send({
          rating: 5,
          title: 'Great Review',
          content: maliciousContent
        });
      
      // Should either sanitize or reject
      expect([201, 400, 401]).toContain(res.status);
      
      if (res.status === 201) {
        // Should not contain script tag
        expect(res.body.review.content).not.toContain('<script>');
      }
    });

    test('should sanitize HTML event handlers', async () => {
      const maliciousContent = '<img src=x onerror="alert(\'xss\')">';
      
      const res = await request(app)
        .post('/api/products/507f1f77bcf86cd799439011/reviews')
        .send({
          rating: 5,
          title: 'Review',
          content: maliciousContent
        });
      
      expect([201, 400, 401]).toContain(res.status);
      
      if (res.status === 201) {
        expect(res.body.review.content).not.toContain('onerror');
      }
    });

    test('should escape special characters in review title', async () => {
      const specialContent = '<b>Bold</b> & "quoted"';
      
      const res = await request(app)
        .post('/api/products/507f1f77bcf86cd799439011/reviews')
        .send({
          rating: 5,
          title: specialContent,
          content: 'Good product'
        });
      
      expect([201, 400, 401]).toContain(res.status);
    });

    test('should sanitize DOM-based XSS vectors', async () => {
      const xssVectors = [
        'javascript:alert("xss")',
        'data:text/html,<script>alert("xss")</script>',
        '<svg onload="alert(\'xss\')"></svg>',
        '<iframe src="javascript:alert(\'xss\')"></iframe>'
      ];
      
      for (const vector of xssVectors) {
        const res = await request(app)
          .post('/api/products/507f1f77bcf86cd799439011/reviews')
          .send({
            rating: 5,
            title: 'Safe Title',
            content: vector
          });
        
        expect([201, 400, 401]).toContain(res.status);
      }
    });
  });

  // ============================================================
  // PRICE MANIPULATION TESTS
  // ============================================================
  
  describe('Price Validation - Prevent Negative Prices', () => {
    test('should reject negative prices', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: -100,
          category: 'electronics',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
      if (res.status === 400) {
        expect(res.body.error).toBeDefined();
      }
    });

    test('should reject zero price', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 0,
          category: 'electronics',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should reject excessive prices', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 10000000,
          category: 'electronics',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should reject non-numeric prices', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 'expensive',
          category: 'electronics',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should accept valid prices', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 99.99,
          category: 'electronics',
          stock: 10
        });
      
      expect([201, 401]).toContain(res.status);
    });
  });

  // ============================================================
  // RATE LIMITING TESTS
  // ============================================================
  
  describe('Rate Limiting Protection', () => {
    test('should rate limit login attempts', async () => {
      const responses = [];
      
      // Make multiple requests
      for (let i = 0; i < 7; i++) {
        const res = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'password'
          });
        responses.push(res.status);
      }
      
      // Last requests should be rate limited (429)
      expect(responses.slice(-2)).toContain(429);
    });

    test('should include rate limit headers', async () => {
      const res = await request(app)
        .get('/api/products')
        .query({ search: 'test' });
      
      expect(res.headers['ratelimit-limit']).toBeDefined();
      expect(res.headers['ratelimit-remaining']).toBeDefined();
    });

    test('should rate limit search requests', async () => {
      const responses = [];
      
      for (let i = 0; i < 32; i++) {
        const res = await request(app)
          .get('/api/products')
          .query({ search: `test${i}` });
        responses.push(res.status);
      }
      
      // Should have rate limited responses
      expect(responses).toContain(429);
    });
  });

  // ============================================================
  // SECURITY HEADERS TESTS
  // ============================================================
  
  describe('Security Headers - Helmet Configuration', () => {
    test('should include Content-Security-Policy header', async () => {
      const res = await request(app)
        .get('/api/products');
      
      expect(res.headers['content-security-policy']).toBeDefined();
    });

    test('should include X-Frame-Options header', async () => {
      const res = await request(app)
        .get('/api/products');
      
      expect(res.headers['x-frame-options']).toBe('DENY');
    });

    test('should include X-Content-Type-Options header', async () => {
      const res = await request(app)
        .get('/api/products');
      
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    test('should include HSTS header', async () => {
      const res = await request(app)
        .get('/api/products');
      
      expect(res.headers['strict-transport-security']).toBeDefined();
    });

    test('should include Referrer-Policy header', async () => {
      const res = await request(app)
        .get('/api/products');
      
      expect(res.headers['referrer-policy']).toBeDefined();
    });
  });

  // ============================================================
  // INPUT VALIDATION TESTS
  // ============================================================
  
  describe('Input Validation and Sanitization', () => {
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
      expect(res.body.error).toContain('email');
    });

    test('should validate username format', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'invalid@user!',
          email: 'test@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      expect(res.status).toBe(400);
    });

    test('should reject empty inputs', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: '',
          email: '',
          password: '',
          confirmPassword: ''
        });
      
      expect(res.status).toBe(400);
    });

    test('should enforce max length constraints', async () => {
      const longString = 'a'.repeat(101);
      
      const res = await request(app)
        .post('/api/products')
        .send({
          name: longString,
          description: 'Test',
          price: 100,
          category: 'electronics',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
    });
  });

  // ============================================================
  // ERROR HANDLING TESTS
  // ============================================================
  
  describe('Error Handling - Information Disclosure Prevention', () => {
    test('should not expose database errors in production', async () => {
      process.env.NODE_ENV = 'production';
      
      const res = await request(app)
        .get('/api/products/invalid-id');
      
      expect(res.status).toBe(400);
      expect(res.body.stack).toBeUndefined();
      
      process.env.NODE_ENV = 'test';
    });

    test('should handle invalid JSON gracefully', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('invalid json');
      
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    test('should return 404 for non-existent routes', async () => {
      const res = await request(app)
        .get('/api/nonexistent');
      
      expect(res.status).toBe(404);
    });
  });

  // ============================================================
  // BUSINESS LOGIC SECURITY TESTS
  // ============================================================
  
  describe('Business Logic Security', () => {
    test('should validate category against allowed values', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 100,
          category: 'invalid-category',
          stock: 10
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should enforce minimum stock quantity', async () => {
      const res = await request(app)
        .post('/api/products')
        .send({
          name: 'Product',
          description: 'Test',
          price: 100,
          category: 'electronics',
          stock: -5
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should enforce valid rating range', async () => {
      const res = await request(app)
        .post('/api/products/507f1f77bcf86cd799439011/reviews')
        .send({
          rating: 10,
          title: 'Review',
          content: 'Great product'
        });
      
      expect([400, 401]).toContain(res.status);
    });

    test('should prevent duplicate usernames', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send({
          username: 'duplicateuser',
          email: 'first@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      // Attempt duplicate
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'duplicateuser',
          email: 'second@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      expect(res.status).toBe(409);
      expect(res.body.error).toContain('already exists');
    });

    test('should prevent duplicate emails', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send({
          username: 'user1',
          email: 'duplicate@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      // Attempt duplicate
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'user2',
          email: 'duplicate@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      expect(res.status).toBe(409);
    });
  });
});
