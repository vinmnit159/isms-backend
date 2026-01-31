-- Database initialization script for ISMS
-- This script creates initial data for testing

-- Create sample organization
INSERT INTO "Organization" (id, name, "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655440000', 'Acme Corporation', NOW());

-- Create sample users with different roles
INSERT INTO "User" (id, email, name, role, "organizationId", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-4466554401', 'admin@acme.com', 'System Administrator', 'SUPER_ADMIN', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554402', 'security@acme.com', 'Security Manager', 'SECURITY_OWNER', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554403', 'auditor@acme.com', 'Internal Auditor', 'AUDITOR', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554404', 'contributor@acme.com', 'Security Analyst', 'CONTRIBUTOR', '550e8400-e29b-41d4-a716-446655440000', NOW());

-- Create sample assets
INSERT INTO "Asset" (id, name, type, "ownerId", criticality, description, "organizationId", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-4466554405', 'Customer Database Server', 'DATABASE', '550e8400-e29b-41d4-a716-4466554402', 'CRITICAL', 'Primary customer database with PII data', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554406', 'Web Application Server', 'APPLICATION', '550e8400-e29b-41d4-a716-4466554402', 'HIGH', 'Main customer-facing web application', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554407', 'Office Network Infrastructure', 'NETWORK', '550e8400-e29b-41d4-a716-4466554402', 'MEDIUM', 'Office network switches and routers', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554408', 'AWS S3 Storage', 'CLOUD', '550e8400-e29b-41d4-a716-4466554402', 'HIGH', 'Cloud storage for documents and backups', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-4466554409', 'Employee Laptops', 'ENDPOINT', '550e8400-e29b-41d4-a716-4466554402', 'MEDIUM', 'Company-issued laptops for employees', '550e8400-e29b-41d4-a716-446655440000', NOW());

-- Create sample risks
INSERT INTO "Risk" (id, title, description, impact, likelihood, "riskScore", status, "assetId", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-4466554410', 'Database SQL Injection', 'Potential for SQL injection attacks on customer database', 'CRITICAL', 'MEDIUM', 12, 'OPEN', '550e8400-e29b-41d4-a716-446655405', NOW()),
('550e8400-e29b-41d4-a716-4466554411', 'Web Application DDoS', 'Risk of denial of service attacks on web application', 'HIGH', 'LOW', 8, 'OPEN', '550e8400-e29b-41d4-a716-4466554406', NOW()),
('550e8400-e29b-41d4-a716-4466554412', 'Data Breach via Laptops', 'Unauthorized access risk from lost or stolen laptops', 'HIGH', 'MEDIUM', 12, 'OPEN', '550e8400-e29b-41d4-a716-4466554409', NOW()),
('550e8400-e29b-41d4-a716-4466554413', 'Network Misconfiguration', 'Improper network configuration leading to unauthorized access', 'MEDIUM', 'LOW', 4, 'MITIGATED', '550e8400-e29b-41d4-a716-4466554407', NOW()),
('550e8400-e29b-41d4-a716-4466554414', 'Cloud Data Exposure', 'S3 bucket configured with public access', 'CRITICAL', 'HIGH', 20, 'OPEN', '550e8400-e29b-41d4-a716-4466554408', NOW());

-- Create sample ISO controls
INSERT INTO "Control" (id, "isoReference", title, description, status, justification, "organizationId", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655415', 'A.5.9', 'Protection against malicious code', 'Detection, prevention and protection mechanisms against malicious code', 'IMPLEMENTED', 'Antivirus and endpoint protection deployed', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-446655416', 'A.8.2', 'Privileged access rights', 'Allocation and use of privileged access rights shall be restricted and controlled', 'PARTIALLY_IMPLEMENTED', 'Partially implemented with role-based access', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-446655417', 'A.12.2', 'Controls against malware', 'Implementation of malware detection, prevention and recovery controls', 'IMPLEMENTED', 'Comprehensive anti-malware solution in place', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-446655418', 'A.14.1', 'Network security controls', 'Network segregation, access control, and network services protection', 'NOT_IMPLEMENTED', 'Network security controls need to be implemented', '550e8400-e29b-41d4-a716-446655440000', NOW()),
('550e8400-e29b-41d4-a716-446655419', 'A.9.1', 'Equipment protection', 'Protection against physical and environmental threats', 'IMPLEMENTED', 'Data center with proper physical security', '550e8400-e29b-41d4-a716-446655440000', NOW());

-- Create sample evidence
INSERT INTO "Evidence" (id, type, "fileName", fileUrl, hash, "controlId", "collectedBy", automated, "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655420', 'AUTOMATED', 'antivirus-scan.json', 'https://api.isms.com/evidence/antivirus-scan.json', 'sha256:abc123...', '550e8400-e29b-41d4-a716-446655415', '550e8400-e29b-41d4-a716-446655401', true, NOW()),
('550e8400-e29b-41d4-a716-446655421', 'FILE', 'access-policy.pdf', 'https://api.isms.com/evidence/access-policy.pdf', 'sha256:def456...', '550e8400-e29b-41d4-a716-446655416', '550e8400-e29b-41d4-a716-446655402', false, NOW()),
('550e8400-e29b-41d4-a716-446655422', 'SCREENSHOT', 'malware-dashboard.png', 'https://api.isms.com/evidence/malware-dashboard.png', 'sha256:ghi789...', '550e8400-e29b-41d4-a716-446655417', '550e8400-e29b-41d4-a716-446655403', false, NOW()),
('550e8400-e29b-41d4-a716-446655423', 'LOG', 'network-access.log', 'https://api.isms.com/evidence/network-access.log', 'sha256:jkl012...', '550e8400-e29b-41d4-a716-446655418', '550e8400-e29b-41d4-a716-446655401', true, NOW());

-- Create risk treatments (linking risks to controls)
INSERT INTO "RiskTreatment" (id, "riskId", "controlId", notes) VALUES 
('550e8400-e29b-41d4-a716-446655424', '550e8400-e29b-41d4-a716-446655410', '550e8400-e29b-41d4-a716-446655415', 'Antivirus protection helps prevent malicious code execution'),
('550e8400-e29b-41d4-a716-446655425', '550e8400-e29b-41d4-a716-446655414', '550e8400-e29b-41d4-a716-446655419', 'Physical security controls for data center help with cloud security'),
('550e8400-e29b-41d4-a716-446655426', '550e8400-e29b-41d4-a716-446655412', '550e8400-e29b-41d4-a716-446655417', 'Anti-malware protection on laptops'),
('550e8400-e29b-41d4-a716-446655427', '550e8400-e29b-41d4-a716-446655411', '550e8400-e29b-41d4-a716-446655418', 'Network security controls can help prevent DDoS attacks');

-- Create sample policies
INSERT INTO "Policy" (id, name, version, status, documentUrl, "organizationId", approvedBy, "approvedAt", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655428', 'Information Security Policy', 'v2.1', 'APPROVED', 'https://api.isms.com/policies/info-sec-policy-v2.1.pdf', '550e8400-e29b-41d4-a716-446655401', '2024-01-15T10:00:00Z', NOW()),
('550e8400-e29b-41d4-a716-446655429', 'Access Control Policy', 'v1.8', 'APPROVED', 'https://api.isms.com/policies/access-control-v1.8.pdf', '550e8400-e29b-41d4-a716-446655401', '2024-01-10T14:30:00Z', NOW()),
('550e8400-e29b-41d4-a716-446655430', 'Data Classification Policy', 'v1.5', 'DRAFT', 'https://api.isms.com/policies/data-classification-v1.5-draft.pdf', NULL, NULL, NOW()),
('550e8400-e29b-41d4-a716-446655431', 'Incident Response Policy', 'v3.0', 'APPROVED', 'https://api.isms.com/policies/incident-response-v3.0.pdf', '550e8400-e29b-41d4-a716-446655401', '2024-01-20T09:15:00Z', NOW());

-- Create sample audits
INSERT INTO "Audit" (id, type, auditor, scope, "startDate", "endDate", "organizationId", "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655432', 'INTERNAL', 'John Smith - Internal Auditor', 'Annual Security Controls Assessment', '2024-01-10T09:00:00Z', '2024-01-15T17:00:00Z', '550e8400-e29b-41d4-a716-4466554000', NOW()),
('550e8400-e29b-41d4-a716-446655433', 'EXTERNAL', 'Deloitte & Touche', 'ISO 27001 Certification Audit', '2024-02-01T09:00:00Z', NULL, '550e8400-e29b-41d4-a716-4466554000', NOW()),
('550e8400-e29b-41d4-a716-446655434', 'SURVEILLANCE', 'Security Team', 'Monthly Security Monitoring', '2024-01-25T00:00:00Z', '2024-01-31T23:59:59Z', '550e8400-e29b-41d4-a716-4466554000', NOW());

-- Create sample audit findings
INSERT INTO "AuditFinding" (id, "auditId", "controlId", severity, description, remediation, status, "createdAt") VALUES 
('550e8400-e29b-41d4-a716-446655435', '550e8400-e29b-41d4-a716-446655432', '550e8400-e29b-41d4-a716-446655418', 'MAJOR', 'Network security controls are not implemented', 'Implement network segmentation and access controls', 'OPEN', NOW()),
('550e8400-e29b-41d4-a716-446655436', '550e8400-e29b-41d4-a716-446655432', '550e8400-e29b-41d4-a716-446655416', 'MINOR', 'Privileged access review not documented', 'Implement quarterly privileged access reviews', 'CLOSED', NOW()),
('550e8400-e29b-41d4-a716-446655437', '550e8400-e29b-41d4-a716-446655433', '550e8400-e29b-41d4-a716-446655417', 'OBSERVATION', 'Malware detection logs not properly retained', 'Configure log retention for 90 days', 'OPEN', NOW());

-- Create sample activity logs
INSERT INTO "ActivityLog" (id, "userId", action, entity, "entityId", "timestamp") VALUES 
('550e8400-e29b-41d4-a716-446655438', '550e8400-e29b-41d4-a716-446655401', 'CREATE', 'Risk', '550e8400-e29b-41d4-a716-446655410', NOW()),
('550e8400-e29b-41d4-a716-446655439', '550e8400-e29b-41d4-a716-446655401', 'UPDATE', 'Control', '550e8400-e29b-41d4-a716-446655416', NOW() - INTERVAL '1 hour'),
('550e8400-e29b-41d4-a716-446655440', '550e8400-e29b-41d4-a716-446655401', 'CREATE', 'Evidence', '550e8400-e29b-41d4-a716-446655420', NOW() - INTERVAL '30 minutes'),
('550e8400-e29b-41d4-a716-446655441', '550e8400-e29b-41d4-a716-446655402', 'CREATE', 'Audit', '550e8400-e29b-41d4-a716-446655432', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655442', '550e8400-e29b-41d4-a716-446655401', 'UPDATE', 'Risk', '550e8400-e29b-41d4-a716-446655414', NOW() - INTERVAL '45 minutes');