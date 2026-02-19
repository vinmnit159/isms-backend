/**
 * github-asset-risk.ts
 *
 * After a GitHub repo scan, this module:
 *  1. Upserts a SAAS Asset for "GitHub Organisation" (parent)
 *  2. Upserts an APPLICATION Asset per repo
 *  3. Creates/updates aggregated Risks for each failing control check
 *  4. Updates the corresponding ISO Control status (IMPLEMENTED / PARTIALLY / NOT_IMPLEMENTED)
 */

import { prisma } from '../../lib/prisma';

// ─── Criticality derivation ───────────────────────────────────────────────────

function deriveCriticality(repo: any): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  if (repo.archived) return 'LOW';
  const name: string = (repo.name ?? '').toLowerCase();
  if (name.includes('infra') || name.includes('terraform') || name.includes('k8s')) return 'CRITICAL';
  if (!repo.private) return 'HIGH'; // public repo = HIGH
  if (
    name.includes('backend') ||
    name.includes('api') ||
    name.includes('auth') ||
    name.includes('server')
  )
    return 'HIGH';
  if (name.includes('test') || name.includes('demo') || name.includes('example')) return 'LOW';
  return 'MEDIUM';
}

// ─── Risk score matrix ────────────────────────────────────────────────────────

const LEVEL_VALUE: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function calcScore(impact: string, likelihood: string): number {
  return (LEVEL_VALUE[impact] ?? 2) * (LEVEL_VALUE[likelihood] ?? 2);
}

// ─── Check definitions ────────────────────────────────────────────────────────

interface CheckDef {
  key: string; // key in scanResult
  isoRef: string;
  riskTitle: (repo: string) => string;
  riskDesc: (repo: string) => string;
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  likelihood: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

const CHECKS: CheckDef[] = [
  {
    key: 'branchProtection',
    isoRef: 'A.8.32',
    riskTitle: (r) => `Branch protection not enabled on ${r}`,
    riskDesc: (r) =>
      `Repository ${r} has no required pull request reviews or status checks on the default branch, allowing unreviewed code to reach production.`,
    impact: 'HIGH',
    likelihood: 'MEDIUM',
  },
  {
    key: 'commitSigning',
    isoRef: 'A.8.24',
    riskTitle: (r) => `Commit signing not enforced on ${r}`,
    riskDesc: (r) =>
      `Less than 80% of recent commits in ${r} are cryptographically signed, making it impossible to verify code authorship.`,
    impact: 'HIGH',
    likelihood: 'MEDIUM',
  },
  {
    key: 'cicd',
    isoRef: 'A.8.25',
    riskTitle: (r) => `No CI/CD pipeline detected in ${r}`,
    riskDesc: (r) =>
      `Repository ${r} has no GitHub Actions workflows, indicating a lack of automated security testing in the SDLC.`,
    impact: 'MEDIUM',
    likelihood: 'MEDIUM',
  },
  {
    key: 'accessControl',
    isoRef: 'A.5.15',
    riskTitle: (r) => `Excessive collaborator access on ${r}`,
    riskDesc: (r) =>
      `Repository ${r} has external collaborators or more than 3 admins, violating least-privilege access control principles.`,
    impact: 'HIGH',
    likelihood: 'HIGH',
  },
  {
    key: 'repoMeta',
    isoRef: 'A.5.15',
    riskTitle: (r) => `Public repository exposure: ${r}`,
    riskDesc: (r) =>
      `Repository ${r} is publicly visible, potentially exposing proprietary code, credentials, or internal architecture.`,
    impact: 'HIGH',
    likelihood: 'HIGH',
  },
];

// ─── Main function ────────────────────────────────────────────────────────────

export async function upsertAssetsAndRisks(
  organizationId: string,
  orgAdminId: string, // used as ownerId for assets
  repos: any[],       // raw GitHub repo objects
  scanResults: Map<number, any> // githubId → scanResult
) {
  // 1. Upsert GitHub Organisation parent asset (SAAS)
  const orgAsset = await upsertGitHubOrgAsset(organizationId, orgAdminId);

  // Track per-check pass/fail across all repos for control status update
  const checkPassCounts: Record<string, { pass: number; total: number }> = {};
  CHECKS.forEach((c) => {
    checkPassCounts[c.key] = { pass: 0, total: 0 };
  });

  for (const repo of repos) {
    const scan = scanResults.get(repo.id);
    if (!scan) continue;

    // 2. Upsert per-repo asset (APPLICATION)
    const repoAsset = await upsertRepoAsset(organizationId, orgAdminId, repo, orgAsset.id);

    // 3. Per check — create risk if failing, accumulate counts
    for (const check of CHECKS) {
      const checkData = scan[check.key];
      if (!checkData) continue;

      const compliant: boolean | null = checkData.result?.compliant ?? null;
      const counts = checkPassCounts[check.key];
      if (!counts) continue;
      counts.total++;
      if (compliant === true) {
        counts.pass++;
      } else if (compliant === false) {
        // Create/update aggregated risk for this repo+check
        await upsertRisk(organizationId, repoAsset.id, check, repo.full_name);
      }
    }
  }

  // 4. Update ISO control statuses based on aggregate pass rates
  await updateControlStatuses(organizationId, checkPassCounts);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function upsertGitHubOrgAsset(organizationId: string, ownerId: string) {
  const name = 'GitHub Organisation';
  const existing = await prisma.asset.findFirst({
    where: { organizationId, name, type: 'SAAS' },
  });
  if (existing) return existing;
  return prisma.asset.create({
    data: {
      name,
      type: 'SAAS',
      ownerId,
      criticality: 'HIGH',
      description: 'GitHub SaaS platform hosting all source code repositories',
      organizationId,
    },
  });
}

async function upsertRepoAsset(
  organizationId: string,
  ownerId: string,
  repo: any,
  parentAssetId: string
) {
  const criticality = deriveCriticality(repo);
  const description = [
    `GitHub repository — ${repo.visibility ?? (repo.private ? 'private' : 'public')}`,
    `Default branch: ${repo.default_branch}`,
    repo.archived ? 'ARCHIVED' : null,
    repo.html_url,
  ]
    .filter(Boolean)
    .join(' | ');

  const existing = await prisma.asset.findFirst({
    where: { organizationId, name: repo.full_name, type: 'APPLICATION' },
  });

  if (existing) {
    return prisma.asset.update({
      where: { id: existing.id },
      data: { criticality, description },
    });
  }

  return prisma.asset.create({
    data: {
      name: repo.full_name,
      type: 'APPLICATION',
      ownerId,
      criticality,
      description,
      organizationId,
    },
  });
}

async function upsertRisk(
  organizationId: string,
  assetId: string,
  check: CheckDef,
  repoFullName: string
) {
  const title = check.riskTitle(repoFullName);
  const existing = await prisma.risk.findFirst({
    where: { assetId, title },
  });

  const riskScore = calcScore(check.impact, check.likelihood);

  if (existing) {
    // Keep status as OPEN if already open; don't downgrade a MITIGATED risk
    if (existing.status === 'OPEN') return existing;
    return prisma.risk.update({
      where: { id: existing.id },
      data: { status: 'OPEN', riskScore },
    });
  }

  return prisma.risk.create({
    data: {
      title,
      description: check.riskDesc(repoFullName),
      impact: check.impact,
      likelihood: check.likelihood,
      riskScore,
      status: 'OPEN',
      assetId,
    },
  });
}

async function updateControlStatuses(
  organizationId: string,
  checkPassCounts: Record<string, { pass: number; total: number }>
) {
  // Map check key → ISO references to update
  const isoMap: Record<string, string[]> = {
    branchProtection: ['A.8.32'],
    commitSigning: ['A.8.24'],
    cicd: ['A.8.25'],
    accessControl: ['A.5.15', 'A.5.18'],
    repoMeta: ['A.5.15'],
  };

  // Merge pass rates for controls that appear in multiple checks (e.g. A.5.15)
  const controlPassRate: Record<string, { pass: number; total: number }> = {};

  for (const [checkKey, isoRefs] of Object.entries(isoMap)) {
    const counts = checkPassCounts[checkKey];
    if (!counts || counts.total === 0) continue;
    for (const isoRef of isoRefs) {
      if (!controlPassRate[isoRef]) controlPassRate[isoRef] = { pass: 0, total: 0 };
      controlPassRate[isoRef].pass += counts.pass;
      controlPassRate[isoRef].total += counts.total;
    }
  }

  for (const [isoRef, { pass, total }] of Object.entries(controlPassRate)) {
    if (total === 0) continue;
    const rate = pass / total;
    const newStatus =
      rate === 1
        ? 'IMPLEMENTED'
        : rate >= 0.5
        ? 'PARTIALLY_IMPLEMENTED'
        : 'NOT_IMPLEMENTED';

    await prisma.control.updateMany({
      where: {
        organizationId,
        isoReference: { contains: isoRef },
      },
      data: { status: newStatus as any },
    });
  }
}
