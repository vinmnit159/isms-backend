import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { Role, AssetType, RiskLevel, RiskStatus, ControlStatus, EvidenceType } from './rbac';

// ISO Controls Data
export const ISO_ANNEX_A_CONTROLS = [
  // =========================
  // A.5 Organizational controls (37)
  // =========================
  { isoReference: "A.5.1", title: "Policies for information security", description: "Information security policy shall be defined, approved by management, published and communicated." },
  { isoReference: "A.5.2", title: "Information security roles and responsibilities", description: "Information security roles and responsibilities shall be defined and allocated." },
  { isoReference: "A.5.3", title: "Segregation of duties", description: "Conflicting duties and areas of responsibility shall be segregated." },
  { isoReference: "A.5.4", title: "Management responsibilities", description: "Management shall require information security to be applied in accordance with policies." },
  { isoReference: "A.5.5", title: "Contact with authorities", description: "The organization shall establish and maintain contact with relevant authorities." },
  { isoReference: "A.5.6", title: "Contact with special interest groups", description: "Contact with special interest groups or forums shall be maintained." },
  { isoReference: "A.5.7", title: "Threat intelligence", description: "Information relating to information security threats shall be collected and analyzed." },
  { isoReference: "A.5.8", title: "Information security in project management", description: "Information security shall be integrated into project management." },
  { isoReference: "A.5.9", title: "Inventory of information and other associated assets", description: "An inventory of information and associated assets shall be developed and maintained." },
  { isoReference: "A.5.10", title: "Acceptable use of information and other associated assets", description: "Rules for acceptable use of information and assets shall be identified and documented." },
  { isoReference: "A.5.11", title: "Return of assets", description: "Assets shall be returned upon termination or change of employment." },
  { isoReference: "A.5.12", title: "Classification of information", description: "Information shall be classified according to sensitivity and criticality." },
  { isoReference: "A.5.13", title: "Labelling of information", description: "Information shall be labelled according to its classification." },
  { isoReference: "A.5.14", title: "Information transfer", description: "Rules for information transfer shall be established." },
  { isoReference: "A.5.15", title: "Access control", description: "Access to information shall be restricted based on business requirements." },
  { isoReference: "A.5.16", title: "Identity management", description: "The full lifecycle of identities shall be managed." },
  { isoReference: "A.5.17", title: "Authentication information", description: "Authentication information shall be protected." },
  { isoReference: "A.5.18", title: "Access rights", description: "Access rights shall be provisioned, reviewed, modified and removed." },
  { isoReference: "A.5.19", title: "Information security in supplier relationships", description: "Information security requirements shall be addressed in supplier relationships." },
  { isoReference: "A.5.20", title: "Addressing information security within supplier agreements", description: "Relevant security requirements shall be established and agreed with suppliers." },
  { isoReference: "A.5.21", title: "Managing information security in the ICT supply chain", description: "Processes shall be implemented to manage ICT supply chain risks." },
  { isoReference: "A.5.22", title: "Monitoring, review and change management of supplier services", description: "Supplier services shall be monitored and reviewed." },
  { isoReference: "A.5.23", title: "Information security for use of cloud services", description: "Information security requirements for cloud services shall be specified." },
  { isoReference: "A.5.24", title: "Information security incident management planning and preparation", description: "Plans and procedures for incident management shall be defined." },
  { isoReference: "A.5.25", title: "Assessment and decision on information security events", description: "Events shall be assessed to determine if they are incidents." },
  { isoReference: "A.5.26", title: "Response to information security incidents", description: "Information security incidents shall be responded to." },
  { isoReference: "A.5.27", title: "Learning from information security incidents", description: "Knowledge gained from incidents shall be used to reduce likelihood or impact." },
  { isoReference: "A.5.28", title: "Collection of evidence", description: "Evidence related to information security events shall be collected and preserved." },
  { isoReference: "A.5.29", title: "Information security during disruption", description: "Information security shall be maintained during disruption." },
  { isoReference: "A.5.30", title: "ICT readiness for business continuity", description: "ICT continuity shall be planned and tested." },
  { isoReference: "A.5.31", title: "Legal, statutory, regulatory and contractual requirements", description: "Requirements shall be identified and complied with." },
  { isoReference: "A.5.32", title: "Intellectual property rights", description: "IP rights shall be protected." },
  { isoReference: "A.5.33", title: "Protection of records", description: "Records shall be protected from loss, destruction and falsification." },
  { isoReference: "A.5.34", title: "Privacy and protection of PII", description: "PII shall be protected in accordance with laws and regulations." },
  { isoReference: "A.5.35", title: "Independent review of information security", description: "Independent reviews shall be conducted." },
  { isoReference: "A.5.36", title: "Compliance with policies and standards", description: "Compliance with security policies shall be reviewed." },
  { isoReference: "A.5.37", title: "Technical compliance review", description: "Information systems shall be reviewed for compliance." },

  // =========================
  // A.6 People controls (8)
  // =========================
  { isoReference: "A.6.1", title: "Screening", description: "Background verification shall be performed in accordance with laws." },
  { isoReference: "A.6.2", title: "Terms and conditions of employment", description: "Security responsibilities shall be included in employment terms." },
  { isoReference: "A.6.3", title: "Information security awareness, education and training", description: "Personnel shall receive appropriate security training." },
  { isoReference: "A.6.4", title: "Disciplinary process", description: "A disciplinary process shall be in place for security violations." },
  { isoReference: "A.6.5", title: "Responsibilities after termination or change of employment", description: "Security responsibilities shall remain after termination." },
  { isoReference: "A.6.6", title: "Confidentiality or non-disclosure agreements", description: "Confidentiality agreements shall be signed." },
  { isoReference: "A.6.7", title: "Remote working", description: "Security measures shall be implemented for remote working." },
  { isoReference: "A.6.8", title: "Information security event reporting", description: "Security events shall be reported through appropriate channels." },

  // =========================
  // A.7 Physical controls (14)
  // =========================
  { isoReference: "A.7.1", title: "Physical security perimeters", description: "Security perimeters shall be defined and protected." },
  { isoReference: "A.7.2", title: "Physical entry controls", description: "Physical access shall be controlled." },
  { isoReference: "A.7.3", title: "Securing offices, rooms and facilities", description: "Facilities shall be secured." },
  { isoReference: "A.7.4", title: "Physical security monitoring", description: "Facilities shall be monitored." },
  { isoReference: "A.7.5", title: "Protecting against physical and environmental threats", description: "Protection against physical threats shall be designed and implemented." },
  { isoReference: "A.7.6", title: "Working in secure areas", description: "Procedures for working in secure areas shall be defined." },
  { isoReference: "A.7.7", title: "Clear desk and clear screen", description: "Clear desk and screen rules shall be implemented." },
  { isoReference: "A.7.8", title: "Equipment sitting and protection", description: "Equipment shall be protected from threats." },
  { isoReference: "A.7.9", title: "Security of assets off-premises", description: "Assets outside premises shall be protected." },
  { isoReference: "A.7.10", title: "Storage media", description: "Storage media shall be managed securely." },
  { isoReference: "A.7.11", title: "Supporting utilities", description: "Utilities shall support security requirements." },
  { isoReference: "A.7.12", title: "Cabling security", description: "Cables shall be protected from interception or damage." },
  { isoReference: "A.7.13", title: "Equipment maintenance", description: "Equipment shall be maintained correctly." },
  { isoReference: "A.7.14", title: "Secure disposal or reuse of equipment", description: "Equipment shall be securely disposed or reused." },

  // =========================
  // A.8 Technological controls (34)
  // =========================
  { isoReference: "A.8.1", title: "User endpoint devices", description: "Endpoint devices shall be protected." },
  { isoReference: "A.8.2", title: "Privileged access rights", description: "Privileged access shall be restricted and controlled." },
  { isoReference: "A.8.3", title: "Information access restriction", description: "Access to information shall be restricted." },
  { isoReference: "A.8.4", title: "Access to source code", description: "Access to source code shall be controlled." },
  { isoReference: "A.8.5", title: "Secure authentication", description: "Secure authentication technologies shall be used." },
  { isoReference: "A.8.6", title: "Capacity management", description: "Resources shall be monitored and adjusted." },
  { isoReference: "A.8.7", title: "Protection against malware", description: "Protection against malware shall be implemented." },
  { isoReference: "A.8.8", title: "Management of technical vulnerabilities", description: "Vulnerabilities shall be identified and addressed." },
  { isoReference: "A.8.9", title: "Configuration management", description: "Configurations shall be managed." },
  { isoReference: "A.8.10", title: "Information deletion", description: "Information shall be securely deleted when no longer required." },
  { isoReference: "A.8.11", title: "Data masking", description: "Data masking shall be applied where appropriate." },
  { isoReference: "A.8.12", title: "Data leakage prevention", description: "Measures shall be taken to prevent data leakage." },
  { isoReference: "A.8.13", title: "Information backup", description: "Backups shall be performed and tested." },
  { isoReference: "A.8.14", title: "Redundancy of information processing facilities", description: "Redundancy shall be implemented." },
  { isoReference: "A.8.15", title: "Logging", description: "Logs shall be produced and protected." },
  { isoReference: "A.8.16", title: "Monitoring activities", description: "Systems shall be monitored." },
  { isoReference: "A.8.17", title: "Clock synchronization", description: "System clocks shall be synchronized." },
  { isoReference: "A.8.18", title: "Use of privileged utility programs", description: "Use of utilities shall be restricted." },
  { isoReference: "A.8.19", title: "Installation of software on operational systems", description: "Software installation shall be controlled." },
  { isoReference: "A.8.20", title: "Networks security", description: "Networks shall be protected." },
  { isoReference: "A.8.21", title: "Security of network services", description: "Network services shall be secured." },
  { isoReference: "A.8.22", title: "Segregation of networks", description: "Networks shall be segregated." },
  { isoReference: "A.8.23", title: "Web filtering", description: "Access to external websites shall be controlled." },
  { isoReference: "A.8.24", title: "Use of cryptography", description: "Cryptographic controls shall be implemented." },
  { isoReference: "A.8.25", title: "Secure development life cycle", description: "Security shall be integrated into development." },
  { isoReference: "A.8.26", title: "Application security requirements", description: "Security requirements shall be defined." },
  { isoReference: "A.8.27", title: "Secure system architecture and engineering principles", description: "Secure design principles shall be applied." },
  { isoReference: "A.8.28", title: "Secure coding", description: "Secure coding practices shall be followed." },
  { isoReference: "A.8.29", title: "Security testing in development and acceptance", description: "Security testing shall be conducted." },
  { isoReference: "A.8.30", title: "Outsourced development", description: "Outsourced development shall be controlled." },
  { isoReference: "A.8.31", title: "Separation of development, test and production environments", description: "Environments shall be segregated." },
  { isoReference: "A.8.32", title: "Change management", description: "Changes shall be controlled." },
  { isoReference: "A.8.33", title: "Test information", description: "Test data shall be protected." },
  { isoReference: "A.8.34", title: "Protection of information systems during audit testing", description: "Audit testing shall not compromise security." }
];

// Default Policies
export const DEFAULT_POLICIES = [
  {
    name: "Information Security Policy",
    version: "1.0",
    status: "DRAFT",
    description: "Defines the organization's approach to information security."
  },
  {
    name: "Access Control Policy",
    version: "1.0", 
    status: "DRAFT",
    description: "Defines rules for access provisioning, review, and revocation."
  },
  {
    name: "Risk Management Policy",
    version: "1.0",
    status: "DRAFT",
    description: "Defines how information security risks are identified and treated."
  },
  {
    name: "Incident Response Policy",
    version: "1.0",
    status: "DRAFT",
    description: "Defines how information security incidents are managed."
  },
  {
    name: "Secure Development Policy",
    version: "1.0",
    status: "DRAFT",
    description: "Defines secure development and change management practices."
  }
];

export async function seedDatabase(prisma: PrismaClient) {
  console.log('🌱 Starting database seeding...');

  try {
    // Check if data already exists
    const existingOrg = await prisma.organization.findFirst();
    if (existingOrg) {
      console.log('📦 Database already seeded. Skipping...');
      return;
    }

    // 1. Create Organization
    console.log('🏢 Creating organization...');
    const organization = await prisma.organization.create({
      data: {
        name: "Demo Organization",
      },
    });

    // 2. Create SUPER_ADMIN user (for signup flow)
    console.log('👤 Creating SUPER_ADMIN user...');
    const hashedPassword = await bcrypt.hash('admin123', 12);
    const superAdmin = await prisma.user.create({
      data: {
        email: 'admin@demo.com',
        password: hashedPassword,
        name: 'System Administrator',
        role: Role.SUPER_ADMIN,
        organizationId: organization.id,
      },
    });

    // 3. Create ORG_ADMIN user
    console.log('👤 Creating ORG_ADMIN user...');
    const orgAdminPassword = await bcrypt.hash('orgadmin123', 12);
    const orgAdmin = await prisma.user.create({
      data: {
        email: 'orgadmin@demo.com',
        password: orgAdminPassword,
        name: 'Organization Administrator',
        role: Role.ORG_ADMIN,
        organizationId: organization.id,
      },
    });

    // 4. Create sample assets
    console.log('💻 Creating sample assets...');
    const assets = await Promise.all([
      prisma.asset.create({
        data: {
          name: "Primary Database Server",
          type: AssetType.DATABASE,
          criticality: RiskLevel.CRITICAL,
          description: "Main PostgreSQL database server",
          ownerId: superAdmin.id,
          organizationId: organization.id,
        },
      }),
      prisma.asset.create({
        data: {
          name: "Web Application Server",
          type: AssetType.APPLICATION,
          criticality: RiskLevel.HIGH,
          description: "Frontend web application server",
          ownerId: orgAdmin.id,
          organizationId: organization.id,
        },
      }),
      prisma.asset.create({
        data: {
          name: "Cloud Infrastructure",
          type: AssetType.CLOUD,
          criticality: RiskLevel.HIGH,
          description: "AWS cloud resources and services",
          ownerId: superAdmin.id,
          organizationId: organization.id,
        },
      }),
    ]);

    // 5. Create sample risks
    console.log('⚠️ Creating sample risks...');
    await Promise.all([
      prisma.risk.create({
        data: {
          title: "Unauthorized Data Access",
          description: "Risk of unauthorized access to sensitive data",
          impact: RiskLevel.HIGH,
          likelihood: RiskLevel.MEDIUM,
          riskScore: 12, // 3 * 4
          status: RiskStatus.OPEN,
          assetId: assets[0].id,
        },
      }),
      prisma.risk.create({
        data: {
          title: "System Downtime",
          description: "Risk of extended system downtime affecting operations",
          impact: RiskLevel.MEDIUM,
          likelihood: RiskLevel.LOW,
          riskScore: 2, // 2 * 1
          status: RiskStatus.OPEN,
          assetId: assets[1].id,
        },
      }),
    ]);

    // 6. Seed ISO controls
    console.log('📋 Seeding ISO 27001 controls...');
    const controls = await Promise.all(
      ISO_ANNEX_A_CONTROLS.map((control, index) =>
        prisma.control.create({
          data: {
            isoReference: control.isoReference,
            title: control.title,
            description: control.description,
            status: ControlStatus.NOT_IMPLEMENTED,
            organizationId: organization.id,
          },
        })
      )
    );

    // 7. Create default policies
    console.log('📄 Creating default policies...');
    await Promise.all(
      DEFAULT_POLICIES.map((policy) =>
        prisma.policy.create({
          data: {
            name: policy.name,
            version: policy.version,
            status: policy.status,
            description: policy.description,
            documentUrl: `https://docs.demo.com/policies/${policy.name.toLowerCase().replace(/\s+/g, '-')}`,
            approvedBy: superAdmin.id,
            approvedAt: new Date(),
            organizationId: organization.id,
          },
        })
      )
    );

    // 8. Create sample evidence for key controls
    console.log('📎 Creating sample evidence...');
    const keyControls = controls.slice(0, 5); // First 5 controls
    await Promise.all(
      keyControls.map((control, index) =>
        prisma.evidence.create({
          data: {
            type: EvidenceType.FILE,
            fileName: `control-evidence-${index + 1}.pdf`,
            fileUrl: `https://docs.demo.com/evidence/control-${index + 1}`,
            hash: `hash-${index + 1}`,
            controlId: control.id,
            collectedBy: superAdmin.id,
            automated: false,
          },
        })
      )
    );

    // 9. Create sample audit
    console.log('🔍 Creating sample audit...');
    const audit = await prisma.audit.create({
      data: {
        type: 'INTERNAL' as any,
        auditor: 'Internal Security Team',
        scope: 'ISO 27001 Implementation Review',
        startDate: new Date(),
        endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        organizationId: organization.id,
      },
    });

    // 10. Create sample audit findings
    console.log('📝 Creating sample audit findings...');
    await Promise.all([
      prisma.auditFinding.create({
        data: {
          auditId: audit.id,
          controlId: controls[0].id, // First control
          severity: 'MAJOR' as any,
          description: 'Control not properly implemented according to policy requirements',
          remediation: 'Implement control procedures and document evidence',
          status: 'OPEN',
        },
      }),
      prisma.auditFinding.create({
        data: {
          auditId: audit.id,
          controlId: controls[1].id, // Second control
          severity: 'MINOR' as any,
          description: 'Minor documentation gaps found',
          remediation: 'Update documentation and maintain records',
          status: 'OPEN',
        },
      }),
    ]);

    console.log('✅ Database seeded successfully!');
    console.log('\n🔑 Demo Login Credentials:');
    console.log('================================');
    console.log('SUPER_ADMIN: admin@demo.com / admin123');
    console.log('ORG_ADMIN:  orgadmin@demo.com / orgadmin123');
    console.log('================================\n');

  } catch (error) {
    console.error('❌ Error seeding database:', error);
    throw error;
  }
}