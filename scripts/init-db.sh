#!/bin/bash

# Railway Database Initialization Script
# This script initializes the database for Railway deployment

set -e

echo "Starting database initialization..."

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Run database migrations
echo "Running database migrations..."
npx prisma migrate deploy

# Check if seeding is needed (only in development or when explicitly requested)
if [ "$NODE_ENV" = "development" ] || [ "$SEED_DATABASE" = "true" ]; then
  echo "Seeding database..."
  npm run seed
else
  echo "Skipping database seeding (production mode)"
fi

echo "Database initialization completed!"