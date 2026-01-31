export const authService = {
  async generateToken(user: { id: string; email: string; role: string }) {
    // JWT token generation is handled in routes
    return null;
  },
  
  async validateToken(token: string) {
    // JWT validation is handled by fastify-jwt plugin
    return null;
  },
  
  async hashPassword(password: string): Promise<string> {
    const bcrypt = require('bcryptjs');
    const { authConfig } = require('../../config/auth');
    return bcrypt.hash(password, authConfig.bcryptRounds);
  },
  
  async comparePassword(password: string, hash: string): Promise<boolean> {
    const bcrypt = require('bcryptjs');
    return bcrypt.compare(password, hash);
  },
};