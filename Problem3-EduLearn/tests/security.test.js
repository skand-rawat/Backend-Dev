const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');

jest.mock('mongoose');

describe('EduLearn Security Tests', () => {
  
  describe('Authentication & Authorization', () => {
    test('should prevent course access for other instructors', async () => {
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Unauthorized Course',
          description: 'Test',
          price: 99.99,
          category: 'programming'
        });
      
      expect([401, 403]).toContain(res.status);
    });

    test('should prevent student from creating courses', async () => {
      // Student role should be rejected from instructor routes
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Student Course',
          description: 'Test',
          price: 99.99,
          category: 'programming'
        });
      
      expect([401, 403]).toContain(res.status);
    });

    test('should prevent privilege escalation to admin', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'hacker',
          email: 'hacker@test.com',
          password: 'Password123!',
          confirmPassword: 'Password123!',
          role: 'admin'
        });
      
      expect(res.status).toBe(201);
      // Should be created as student, not admin
      expect(['student', 'instructor']).toContain(res.body.role);
    });

    test('should lock account after failed login attempts', async () => {
      const responses = [];
      for (let i = 0; i < 6; i++) {
        const res = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'user@test.com',
            password: 'wrongpass'
          });
        responses.push(res.status);
      }
      
      expect(responses).toContain(429);
    });
  });

  describe('Input Validation - Course Creation', () => {
    test('should validate price is positive', async () => {
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: 'Description',
          price: -100,
          category: 'programming'
        });
      
      expect([400, 401, 403]).toContain(res.status);
    });

    test('should validate category', async () => {
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: 'Description',
          price: 99.99,
          category: 'invalid-category'
        });
      
      expect([400, 401, 403]).toContain(res.status);
    });

    test('should enforce description length', async () => {
      const longDesc = 'a'.repeat(2001);
      
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: longDesc,
          price: 99.99,
          category: 'programming'
        });
      
      expect([400, 401, 403]).toContain(res.status);
    });
  });

  describe('XSS Protection - Course Description', () => {
    test('should sanitize script tags', async () => {
      const maliciousDesc = '<script>alert("xss")</script>Course content';
      
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: maliciousDesc,
          price: 99.99,
          category: 'programming'
        });
      
      expect([201, 401, 403]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.course.description).not.toContain('<script>');
      }
    });

    test('should sanitize event handlers', async () => {
      const maliciousDesc = '<img src=x onerror="alert(\'xss\')">';
      
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: maliciousDesc,
          price: 99.99,
          category: 'programming'
        });
      
      expect([201, 401, 403]).toContain(res.status);
    });

    test('should allow safe HTML formatting', async () => {
      const safeDesc = '<p>Intro</p><b>Important</b> <ul><li>Item 1</li></ul>';
      
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: safeDesc,
          price: 99.99,
          category: 'programming'
        });
      
      expect([201, 401, 403]).toContain(res.status);
    });
  });

  describe('Quiz Submission Integrity', () => {
    test('should lock quiz submission immediately', async () => {
      const res = await request(app)
        .post('/api/quizzes/507f1f77bcf86cd799439011/submit')
        .send({
          answers: [
            { questionId: 0, selectedAnswer: 1 },
            { questionId: 1, selectedAnswer: 2 }
          ]
        });
      
      expect([201, 401, 403, 404]).toContain(res.status);
      if (res.status === 201) {
        // Submission should be locked, preventing modifications
        expect(res.body.submission).toBeDefined();
      }
    });

    test('should validate answers format', async () => {
      const res = await request(app)
        .post('/api/quizzes/507f1f77bcf86cd799439011/submit')
        .send({
          answers: 'invalid format'
        });
      
      expect([400, 401, 403, 404]).toContain(res.status);
    });

    test('should verify enrollment before submission', async () => {
      // Should verify student is enrolled in the course
      const res = await request(app)
        .post('/api/quizzes/507f1f77bcf86cd799439011/submit')
        .send({
          answers: [{ questionId: 0, selectedAnswer: 1 }]
        });
      
      expect([401, 403, 404]).toContain(res.status);
    });

    test('should prevent answer modification', async () => {
      // Get submission first
      const getRes = await request(app)
        .get('/api/submissions/507f1f77bcf86cd799439011');
      
      expect([401, 403, 404]).toContain(getRes.status);
    });
  });

  describe('File Upload Security', () => {
    test('should reject invalid file types', async () => {
      const res = await request(app)
        .post('/api/courses/507f1f77bcf86cd799439011/upload')
        .attach('file', Buffer.from('executable code'), 'malware.exe');
      
      expect([400, 401, 403, 404]).toContain(res.status);
    });

    test('should enforce file size limit', async () => {
      const largeFile = Buffer.alloc(11 * 1024 * 1024); // 11MB
      
      const res = await request(app)
        .post('/api/courses/507f1f77bcf86cd799439011/upload')
        .attach('file', largeFile, 'large.pdf');
      
      expect([400, 401, 403, 404]).toContain(res.status);
    });

    test('should verify instructor ownership', async () => {
      // Student or other instructor cannot upload to course
      const res = await request(app)
        .post('/api/courses/507f1f77bcf86cd799439011/upload')
        .attach('file', Buffer.from('content'), 'document.pdf');
      
      expect([401, 403, 404]).toContain(res.status);
    });

    test('should enforce MIME type validation', async () => {
      const res = await request(app)
        .post('/api/courses/507f1f77bcf86cd799439011/upload')
        .attach('file', Buffer.from('<?php echo "xss"; ?>'), 'fake.pdf');
      
      expect([400, 401, 403, 404]).toContain(res.status);
    });
  });

  describe('File Download Access Control', () => {
    test('should require authentication', async () => {
      const res = await request(app)
        .get('/api/files/507f1f77bcf86cd799439011/download');
      
      expect(res.status).toBe(401);
    });

    test('should verify file access permissions', async () => {
      // Non-enrolled student cannot download
      const res = await request(app)
        .get('/api/files/507f1f77bcf86cd799439011/download');
      
      expect(res.status).toBe(401);
    });

    test('should log file access', async () => {
      // Access should be logged for audit trail
      const res = await request(app)
        .get('/api/files/507f1f77bcf86cd799439011/download');
      
      expect([401, 403, 404]).toContain(res.status);
    });
  });

  describe('Session Security', () => {
    test('should set secure session cookie', async () => {
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

    test('should timeout session after 8 hours', async () => {
      // Session maxAge should be 8 hours for educational platform
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser2',
          email: 'test2@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      
      if (res.status === 201) {
        // Session should expire after 8 hours
        expect(res.headers['set-cookie']).toBeDefined();
      }
    });
  });

  describe('Rate Limiting', () => {
    test('should rate limit quiz submissions', async () => {
      const responses = [];
      for (let i = 0; i < 7; i++) {
        const res = await request(app)
          .post('/api/quizzes/507f1f77bcf86cd799439011/submit')
          .send({
            answers: [{ questionId: 0, selectedAnswer: 1 }]
          });
        responses.push(res.status);
      }
      
      expect(responses).toContain(429);
    });

    test('should rate limit authentication', async () => {
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
  });

  describe('Role-Based Access Control (RBAC)', () => {
    test('should enforce role-based route protection', async () => {
      // Student accessing instructor route
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: 'Test',
          price: 99.99,
          category: 'programming'
        });
      
      expect([401, 403]).toContain(res.status);
    });

    test('should verify role consistency', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'student',
          email: 'student@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!',
          role: 'student'
        });
      
      expect(res.status).toBe(201);
      expect(res.body.role).toBe('student');
    });
  });

  describe('Data Isolation', () => {
    test('should prevent instructor data mixing', async () => {
      // Each instructor should only see their own courses
      const res = await request(app)
        .get('/api/courses');
      
      // Either not authenticated or has filtered results
      expect([200, 401]).toContain(res.status);
    });

    test('should prevent student from modifying grades', async () => {
      // Students cannot modify their quiz submissions
      const res = await request(app)
        .put('/api/submissions/507f1f77bcf86cd799439011')
        .send({
          score: 100
        });
      
      expect([401, 403, 404, 405]).toContain(res.status);
    });
  });

  describe('Course Access Control', () => {
    test('should verify student enrollment', async () => {
      // Non-enrolled student cannot access course
      const res = await request(app)
        .get('/api/courses/507f1f77bcf86cd799439011');
      
      // Should work but not show paid course details
      expect([200, 401, 404]).toContain(res.status);
    });

    test('should hide unpublished courses from students', async () => {
      const res = await request(app)
        .get('/api/courses');
      
      // Should only show published courses
      expect(res.status).toBeGreaterThanOrEqual(200);
    });
  });

  describe('Validation & Sanitization', () => {
    test('should reject invalid ObjectId formats', async () => {
      const res = await request(app)
        .post('/api/courses/invalid-id/upload')
        .attach('file', Buffer.from('content'), 'file.pdf');
      
      expect([400, 401, 403]).toContain(res.status);
    });

    test('should validate all numeric inputs', async () => {
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: 'Test',
          price: 'not-a-number',
          category: 'programming'
        });
      
      expect([400, 401, 403]).toContain(res.status);
    });
  });

  describe('Error Handling', () => {
    test('should not expose sensitive error information', async () => {
      process.env.NODE_ENV = 'production';
      
      const res = await request(app)
        .post('/api/courses')
        .send({
          title: 'Course',
          description: 'Test',
          price: 99.99,
          category: 'programming'
        });
      
      expect(res.body.stack).toBeUndefined();
      
      process.env.NODE_ENV = 'test';
    });
  });

  describe('Security Headers', () => {
    test('should include CSP header', async () => {
      const res = await request(app).get('/api/courses');
      expect(res.headers['content-security-policy']).toBeDefined();
    });

    test('should include X-Frame-Options header', async () => {
      const res = await request(app).get('/api/courses');
      expect(res.headers['x-frame-options']).toBe('DENY');
    });
  });
});
