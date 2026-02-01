# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install OpenSSL and other system dependencies
RUN apk add --no-cache openssl3

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci && npm cache clean --force

# Copy source code
COPY src/ ./src/
COPY prisma/ ./prisma/

# Generate Prisma client
RUN npx prisma generate

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Install OpenSSL and other system dependencies
RUN apk add --no-cache openssl3

# Install production dependencies only
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Ensure necessary directories exist
RUN mkdir -p /app/node_modules/.prisma

# Copy built application and Prisma client
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/prisma ./prisma

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S isms -u 1001

# Change ownership of the app directory
RUN chown -R isms:nodejs /app
USER isms

# Expose port
EXPOSE 3000

# Health check (using wget for smaller image size)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start the application
CMD ["node", "dist/server.js"]