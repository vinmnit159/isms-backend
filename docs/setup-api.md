# ISMS Setup API Documentation

## Overview
The ISMS backend provides a comprehensive setup API that allows for complete system initialization in a single request.

## Setup Flow

### 1. System Initialization
When the system is first deployed, it can be initialized by calling the setup endpoint. This creates:
- ✅ Organization
- ✅ SUPER_ADMIN user  
- ✅ ORG_ADMIN user
- ✅ Complete ISO 27001 controls (93 controls from Annex A)
- ✅ Default security policies
- ✅ Sample assets and risks
- ✅ Sample audit and findings

### API Endpoints

#### POST `/api/setup/setup`
Initializes the entire system with organization and admin users.

**Request Body:**
```json
{
  "organizationName": "Acme Corporation",
  "adminName": "John Doe",
  "adminEmail": "john@acme.com", 
  "adminPassword": "SecurePassword123!",
  "orgAdminName": "Jane Smith",
  "orgAdminEmail": "jane@acme.com",
  "orgAdminPassword": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Organization and users created successfully",
  "data": {
    "organization": {
      "id": "org-uuid",
      "name": "Acme Corporation",
      "createdAt": "2024-01-01T00:00:00.000Z"
    },
    "superAdmin": {
      "id": "admin-uuid",
      "email": "john@acme.com",
      "name": "John Doe", 
      "role": "SUPER_ADMIN"
    },
    "orgAdmin": {
      "id": "org-admin-uuid",
      "email": "jane@acme.com",
      "name": "Jane Smith",
      "role": "ORG_ADMIN"
    },
    "token": "jwt-token",
    "setupComplete": true
  }
}
```

#### GET `/api/setup/setup-status`
Checks if the system has been initialized.

**Response:**
```json
{
  "setup": true,
  "userCount": 2,
  "organizationCount": 1,
  "canSetup": false
}
```

#### POST `/api/setup/reset-system` (Development only)
Resets the entire system to initial state. **Only available in development mode**.

## Post-Setup Data

### Default Users
- **SUPER_ADMIN**: Full system access, can manage all organizations and users
- **ORG_ADMIN**: Can manage all aspects of their organization

### ISO Controls
All 93 controls from ISO 27001:2013 Annex A are automatically created:
- A.5: Organizational controls (37 controls)
- A.6: People controls (8 controls)  
- A.7: Physical controls (14 controls)
- A.8: Technological controls (34 controls)

### Default Policies
5 default security policies are created:
- Information Security Policy
- Access Control Policy  
- Risk Management Policy
- Incident Response Policy
- Secure Development Policy

### Sample Data
- 3 Sample assets (Database, Application, Cloud)
- 2 Sample risks (Unauthorized Access, System Downtime)
- Sample evidence for first 5 controls
- Sample internal audit with findings

## Authentication
After setup, use the returned JWT token to authenticate with existing endpoints:
- Include in Authorization header: `Bearer <token>`
- Use `/api/auth/me` to verify user details

## Database Seeding

The system can also be seeded manually:

```bash
# Run the seed script
npm run seed

# Or during development setup
npm run start:safe
```

This will create the same comprehensive dataset as the setup API.

## Security Notes

- Setup can only be performed once per system
- SUPER_ADMIN user has system-wide permissions
- ORG_ADMIN user has organization-wide permissions  
- All passwords are hashed using bcrypt (12 rounds)
- JWT tokens include user role and organization ID for authorization