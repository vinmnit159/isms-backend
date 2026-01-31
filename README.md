# ISMS Backend

Information Security Management System Backend API built with Fastify, TypeScript, and Prisma.

## 🚀 Features

- **Authentication & Authorization**: JWT-based auth with role-based access control (RBAC)
- **API Documentation**: Auto-generated OpenAPI/Swagger documentation
- **Database Management**: PostgreSQL with Prisma ORM
- **Type Safety**: Full TypeScript support
- **Testing**: Jest test suite
- **Docker Support**: Production-ready Docker configuration
- **Logging**: Structured logging with Pino
- **Security**: Helmet, CORS, input validation

## 📋 Requirements

- Node.js 18+
- PostgreSQL 12+
- npm or yarn

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd isms-backend
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
```

4. Configure your `.env` file:
```env
DATABASE_URL="postgresql://user:password@localhost:5432/isms_db"
JWT_SECRET="your-super-secret-jwt-key"
NODE_ENV="development"
PORT=3000
CORS_ORIGIN="http://localhost:5173"
```

5. Set up the database:
```bash
npm run migrate
npm run generate
```

6. Seed the database (optional):
```bash
npm run seed
```

## 🚀 Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm run build
npm start
```

## 📚 API Documentation

Once the server is running, you can access the API documentation at:
- Swagger UI: `http://localhost:3000/docs`
- OpenAPI JSON: `http://localhost:3000/docs/json`

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test -- --coverage
```

## 📦 API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user (protected)

### Modules (coming soon)
- `/api/risks` - Risk management
- `/api/controls` - Security controls
- `/api/audits` - Audit management
- `/api/assets` - Asset management
- `/api/evidence` - Evidence management

## 🔐 User Roles & Permissions

### Roles
- **ADMIN**: Full system access
- **MANAGER**: Manage risks, controls, audits, assets
- **USER**: Read-only access and evidence upload

### Permissions
The system uses granular permissions for different actions across modules.

## 🗄️ Database Schema

The application uses the following main entities:
- Users
- Risks
- Controls
- Assets
- Evidence
- Audits
- Frameworks

See `prisma/schema.prisma` for the complete schema definition.

## 🐳 Docker Deployment

### Build Docker Image
```bash
docker build -t isms-backend .
```

### Run with Docker Compose
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://user:password@db:5432/isms_db
      JWT_SECRET: your-secret
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: isms_db
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## 📝 Project Structure

```
isms-backend/
├── src/
│   ├── app.ts              # Fastify instance configuration
│   ├── server.ts           # Application bootstrap
│   ├── config/             # Configuration files
│   ├── modules/            # Business logic modules
│   │   ├── auth/           # Authentication
│   │   ├── risks/          # Risk management
│   │   ├── controls/       # Security controls
│   │   ├── evidence/       # Evidence management
│   │   ├── audits/         # Audit management
│   │   └── users/          # User management
│   ├── lib/                # Shared utilities
│   │   ├── prisma.ts       # Prisma client
│   │   ├── logger.ts       # Logger configuration
│   │   └── rbac.ts         # Role-based access control
│   └── plugins/            # Fastify plugins
│       ├── jwt.ts          # JWT authentication
│       └── swagger.ts      # API documentation
├── prisma/
│   └── schema.prisma       # Database schema
├── openapi/
│   └── openapi.yaml         # API specification
├── tests/                   # Test files
├── Dockerfile              # Docker configuration
└── README.md               # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support, please contact support@isms.com or create an issue in the repository.