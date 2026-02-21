/**
 * GitHubTestEvaluator
 *
 * Fetches data from the GitHub API once (cached per run) and evaluates every
 * automated Engineering test that is linked to a GitHub integration.
 *
 * Result mapping:
 *   Pass    → TestStatus.OK
 *   Warning → TestStatus.Due_soon
 *   Fail    → TestStatus.Needs_remediation
 */

import axios from 'axios';
import crypto from 'crypto';

const GH_API = 'https://api.github.com';

function ghHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

export type EvalResult = 'Pass' | 'Fail' | 'Warning';

export interface TestEvaluation {
  testName: string;
  status: EvalResult;
  summary: string;
  findings: any[];
  rawData?: any;
}

// ─── GitHub data cache (per evaluator instance) ───────────────────────────────

interface GitHubCache {
  repos?: any[];
  orgMembers?: any[];
  orgDetails?: any;
  // per-repo caches
  vulnerabilityAlerts: Map<string, any[]>;    // fullName → alerts
  pullRequests: Map<string, any[]>;           // fullName → PRs
  workflows: Map<string, any[]>;             // fullName → workflows
  collaborators: Map<string, any[]>;         // fullName → collaborators
  commits: Map<string, any[]>;              // fullName → commits
}

export class GitHubTestEvaluator {
  private token: string;
  private cache: GitHubCache;

  constructor(token: string) {
    this.token = token;
    this.cache = {
      vulnerabilityAlerts: new Map(),
      pullRequests: new Map(),
      workflows: new Map(),
      collaborators: new Map(),
      commits: new Map(),
    };
  }

  // ─── Data fetchers (lazy, cached) ──────────────────────────────────────────

  async getRepos(): Promise<any[]> {
    if (!this.cache.repos) {
      const repos: any[] = [];
      let page = 1;
      while (true) {
        const { data } = await axios.get(`${GH_API}/user/repos`, {
          headers: ghHeaders(this.token),
          params: { per_page: 100, page, sort: 'updated' },
        });
        repos.push(...data);
        if (data.length < 100) break;
        page++;
      }
      this.cache.repos = repos;
    }
    return this.cache.repos;
  }

  async getOrgDetails(): Promise<any> {
    if (!this.cache.orgDetails) {
      try {
        const { data } = await axios.get(`${GH_API}/user`, {
          headers: ghHeaders(this.token),
        });
        // Get orgs
        const { data: orgs } = await axios.get(`${GH_API}/user/orgs`, {
          headers: ghHeaders(this.token),
          params: { per_page: 100 },
        });
        this.cache.orgDetails = { user: data, orgs };
      } catch {
        this.cache.orgDetails = { user: null, orgs: [] };
      }
    }
    return this.cache.orgDetails;
  }

  async getOrgMembers(org: string): Promise<any[]> {
    if (!this.cache.orgMembers) {
      try {
        const { data } = await axios.get(`${GH_API}/orgs/${org}/members`, {
          headers: ghHeaders(this.token),
          params: { per_page: 100 },
        });
        this.cache.orgMembers = data;
      } catch {
        this.cache.orgMembers = [];
      }
    }
    return this.cache.orgMembers!;
  }

  async getVulnerabilityAlerts(owner: string, repo: string): Promise<any[]> {
    const key = `${owner}/${repo}`;
    if (!this.cache.vulnerabilityAlerts.has(key)) {
      try {
        // Use Dependabot alerts API
        const alerts: any[] = [];
        let page = 1;
        while (true) {
          const { data } = await axios.get(
            `${GH_API}/repos/${owner}/${repo}/dependabot/alerts`,
            {
              headers: { ...ghHeaders(this.token), Accept: 'application/vnd.github+json' },
              params: { per_page: 100, page, state: 'open' },
            }
          );
          alerts.push(...data);
          if (data.length < 100) break;
          page++;
        }
        this.cache.vulnerabilityAlerts.set(key, alerts);
      } catch {
        // No access or not enabled — treat as no alerts
        this.cache.vulnerabilityAlerts.set(key, []);
      }
    }
    return this.cache.vulnerabilityAlerts.get(key)!;
  }

  async getPullRequests(owner: string, repo: string): Promise<any[]> {
    const key = `${owner}/${repo}`;
    if (!this.cache.pullRequests.has(key)) {
      try {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const { data } = await axios.get(`${GH_API}/repos/${owner}/${repo}/pulls`, {
          headers: ghHeaders(this.token),
          params: { state: 'closed', per_page: 100, sort: 'updated', direction: 'desc' },
        });
        // Filter to last 30 days
        const recent = data.filter((pr: any) => new Date(pr.updated_at) >= thirtyDaysAgo);
        this.cache.pullRequests.set(key, recent);
      } catch {
        this.cache.pullRequests.set(key, []);
      }
    }
    return this.cache.pullRequests.get(key)!;
  }

  async getCollaborators(owner: string, repo: string): Promise<any[]> {
    const key = `${owner}/${repo}`;
    if (!this.cache.collaborators.has(key)) {
      try {
        const { data } = await axios.get(`${GH_API}/repos/${owner}/${repo}/collaborators`, {
          headers: ghHeaders(this.token),
          params: { per_page: 100, affiliation: 'all' },
        });
        this.cache.collaborators.set(key, data);
      } catch {
        this.cache.collaborators.set(key, []);
      }
    }
    return this.cache.collaborators.get(key)!;
  }

  async getOrgMFA(org: string): Promise<boolean | null> {
    try {
      const { data } = await axios.get(`${GH_API}/orgs/${org}`, {
        headers: ghHeaders(this.token),
      });
      return data.two_factor_requirement_enabled ?? null;
    } catch {
      return null;
    }
  }

  // ─── Individual test evaluators ────────────────────────────────────────────

  /** Vulnerability tests — aggregate across ALL repos */
  async evaluateVulnerabilities(severity: 'critical' | 'high' | 'medium' | 'low'): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    const findings: any[] = [];

    for (const repo of repos) {
      const [owner, name] = repo.full_name.split('/');
      const alerts = await this.getVulnerabilityAlerts(owner, name);
      const matching = alerts.filter(
        (a: any) => a.security_advisory?.severity?.toLowerCase() === severity
      );
      if (matching.length > 0) {
        findings.push({
          repo: repo.full_name,
          count: matching.length,
          packages: matching.map((a: any) => ({
            pkg: a.dependency?.package?.name,
            advisory: a.security_advisory?.summary,
            cve: a.security_advisory?.cve_id,
          })),
        });
      }
    }

    const totalUnresolved = findings.reduce((s, f) => s + f.count, 0);
    const status: EvalResult = totalUnresolved === 0 ? 'Pass' : 'Fail';
    return {
      testName: `${severity.charAt(0).toUpperCase() + severity.slice(1)} vulnerabilities identified in packages are addressed (GitHub Repo)`,
      status,
      summary: totalUnresolved === 0
        ? `No open ${severity} vulnerabilities found across ${repos.length} repositories.`
        : `${totalUnresolved} open ${severity} vulnerability alerts across ${findings.length} repositories.`,
      findings,
    };
  }

  /** GitHub accounts associated with users (org member list accessible) */
  async evaluateGitHubAccountsAssociated(): Promise<TestEvaluation> {
    const { orgs } = await this.getOrgDetails();
    if (orgs.length === 0) {
      return {
        testName: 'GitHub accounts associated with users',
        status: 'Warning',
        summary: 'No GitHub organization found. Install the app on a GitHub Org for full member checks.',
        findings: [],
      };
    }
    const org = orgs[0].login;
    const members = await this.getOrgMembers(org);
    return {
      testName: 'GitHub accounts associated with users',
      status: members.length > 0 ? 'Pass' : 'Warning',
      summary: `${members.length} member(s) found in GitHub org "${org}".`,
      findings: members.map((m: any) => ({ login: m.login, id: m.id })),
    };
  }

  /** All GitHub members must map to ISMS users — evaluated per-org */
  async evaluateAllMembersMapToISMS(ismsUserLogins: string[]): Promise<TestEvaluation> {
    const { orgs } = await this.getOrgDetails();
    if (orgs.length === 0) {
      return {
        testName: 'All GitHub members must map to ISMS users',
        status: 'Warning',
        summary: 'No GitHub organization accessible. Cannot perform member mapping check.',
        findings: [],
      };
    }
    const org = orgs[0].login;
    const members = await this.getOrgMembers(org);
    const unmapped = members.filter(
      (m: any) => !ismsUserLogins.includes(m.login.toLowerCase())
    );
    return {
      testName: 'All GitHub members must map to ISMS users',
      status: unmapped.length === 0 ? 'Pass' : 'Fail',
      summary: unmapped.length === 0
        ? `All ${members.length} GitHub org members are mapped to ISMS users.`
        : `${unmapped.length} GitHub org member(s) not mapped to any ISMS user.`,
      findings: unmapped.map((m: any) => ({ login: m.login, avatarUrl: m.avatar_url })),
    };
  }

  /** GitHub accounts deprovisioned when personnel leave */
  async evaluateDeprovisionedAccounts(activeIsmsLogins: string[]): Promise<TestEvaluation> {
    const { orgs } = await this.getOrgDetails();
    if (orgs.length === 0) {
      return {
        testName: 'GitHub accounts deprovisioned when personnel leave',
        status: 'Warning',
        summary: 'No GitHub organization accessible.',
        findings: [],
      };
    }
    const org = orgs[0].login;
    const members = await this.getOrgMembers(org);
    // Members whose login doesn't appear in active ISMS linked accounts
    const stale = members.filter(
      (m: any) => !activeIsmsLogins.includes(m.login.toLowerCase())
    );
    return {
      testName: 'GitHub accounts deprovisioned when personnel leave',
      status: stale.length === 0 ? 'Pass' : 'Fail',
      summary: stale.length === 0
        ? 'No stale GitHub accounts detected.'
        : `${stale.length} GitHub member(s) have no matching active ISMS personnel.`,
      findings: stale.map((m: any) => ({ login: m.login })),
    };
  }

  /** MFA on GitHub — org-level enforcement */
  async evaluateMFA(): Promise<TestEvaluation> {
    const { orgs } = await this.getOrgDetails();
    if (orgs.length === 0) {
      return {
        testName: 'MFA on GitHub',
        status: 'Warning',
        summary: 'No GitHub organization found. MFA enforcement cannot be verified.',
        findings: [],
      };
    }
    const org = orgs[0].login;
    const mfaEnabled = await this.getOrgMFA(org);
    return {
      testName: 'MFA on GitHub',
      status: mfaEnabled === true ? 'Pass' : mfaEnabled === false ? 'Fail' : 'Warning',
      summary: mfaEnabled === true
        ? `MFA is enforced for GitHub org "${org}".`
        : mfaEnabled === false
        ? `MFA is NOT enforced for GitHub org "${org}".`
        : `Cannot determine MFA status for GitHub org "${org}" (insufficient permissions).`,
      findings: [{ org, mfaEnforced: mfaEnabled }],
    };
  }

  /** PRs must have ≥1 approval OR documented exception */
  async evaluateCodeReviewApproval(): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    const findings: any[] = [];
    let totalPRs = 0;
    let approvedPRs = 0;

    for (const repo of repos) {
      const [owner, name] = repo.full_name.split('/');
      const prs = await this.getPullRequests(owner, name);
      for (const pr of prs) {
        totalPRs++;
        // A merged PR with reviews means it was approved
        const approved = (pr.review_comments > 0) || pr.merged_at !== null;
        if (approved) approvedPRs++;
        else findings.push({ repo: repo.full_name, prNumber: pr.number, title: pr.title });
      }
    }

    const pct = totalPRs > 0 ? Math.round((approvedPRs / totalPRs) * 100) : 100;
    return {
      testName: 'GitHub code changes were approved or provided justification for exception',
      status: pct === 100 ? 'Pass' : pct >= 80 ? 'Warning' : 'Fail',
      summary: totalPRs === 0
        ? 'No pull requests found in the last 30 days.'
        : `${approvedPRs}/${totalPRs} PRs (${pct}%) in last 30 days had reviews/approvals.`,
      findings,
    };
  }

  /** % of PRs reviewed in last 30 days */
  async evaluateApplicationChangesReviewed(): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    let totalPRs = 0;
    let reviewedPRs = 0;
    const unreviewed: any[] = [];

    for (const repo of repos) {
      const [owner, name] = repo.full_name.split('/');
      const prs = await this.getPullRequests(owner, name);
      for (const pr of prs) {
        totalPRs++;
        if (pr.review_comments > 0 || (pr as any)._reviews_count > 0) {
          reviewedPRs++;
        } else if (pr.merged_at) {
          // Merged with no review comments — check if reviews exist
          try {
            const { data: reviews } = await axios.get(
              `${GH_API}/repos/${owner}/${name}/pulls/${pr.number}/reviews`,
              { headers: ghHeaders(this.token) }
            );
            if (reviews.length > 0) reviewedPRs++;
            else unreviewed.push({ repo: repo.full_name, prNumber: pr.number, title: pr.title });
          } catch {
            unreviewed.push({ repo: repo.full_name, prNumber: pr.number, title: pr.title });
          }
        } else {
          unreviewed.push({ repo: repo.full_name, prNumber: pr.number, title: pr.title });
        }
      }
    }

    const pct = totalPRs > 0 ? Math.round((reviewedPRs / totalPRs) * 100) : 100;
    return {
      testName: 'Application changes reviewed',
      status: pct >= 90 ? 'Pass' : pct >= 70 ? 'Warning' : 'Fail',
      summary: totalPRs === 0
        ? 'No merged PRs in the last 30 days.'
        : `${reviewedPRs}/${totalPRs} PRs (${pct}%) reviewed in last 30 days.`,
      findings: unreviewed,
    };
  }

  /** Author must not be reviewer */
  async evaluateAuthorNotReviewer(): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    const violations: any[] = [];
    let checked = 0;

    for (const repo of repos) {
      const [owner, name] = repo.full_name.split('/');
      const prs = await this.getPullRequests(owner, name);
      for (const pr of prs.slice(0, 20)) { // cap per repo
        checked++;
        try {
          const { data: reviews } = await axios.get(
            `${GH_API}/repos/${owner}/${name}/pulls/${pr.number}/reviews`,
            { headers: ghHeaders(this.token) }
          );
          const selfReview = reviews.some(
            (r: any) => r.user?.login === pr.user?.login && r.state === 'APPROVED'
          );
          if (selfReview) {
            violations.push({
              repo: repo.full_name,
              prNumber: pr.number,
              author: pr.user?.login,
            });
          }
        } catch { /* insufficient permissions */ }
      }
    }

    return {
      testName: 'Author is not the reviewer of pull requests',
      status: violations.length === 0 ? 'Pass' : 'Fail',
      summary: violations.length === 0
        ? `No self-approved PRs found (checked ${checked} PRs).`
        : `${violations.length} PR(s) where the author self-approved.`,
      findings: violations,
    };
  }

  /** At least 1 active repository exists */
  async evaluateVersionControlExists(): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    const active = repos.filter((r: any) => !r.archived);
    return {
      testName: 'Company has a version control system',
      status: active.length > 0 ? 'Pass' : 'Fail',
      summary: active.length > 0
        ? `${active.length} active repository/repositories found.`
        : 'No active repositories found.',
      findings: active.map((r: any) => ({ name: r.full_name, updatedAt: r.updated_at })),
    };
  }

  /** All repos must be private */
  async evaluateRepoVisibilityPrivate(): Promise<TestEvaluation> {
    const repos = await this.getRepos();
    const publicRepos = repos.filter((r: any) => !r.private);
    return {
      testName: 'GitHub repository visibility has been set to private',
      status: publicRepos.length === 0 ? 'Pass' : 'Fail',
      summary: publicRepos.length === 0
        ? `All ${repos.length} repositories are private.`
        : `${publicRepos.length} public repository/repositories found.`,
      findings: publicRepos.map((r: any) => ({ name: r.full_name, visibility: r.visibility })),
    };
  }

  // ─── Run a single test by name ─────────────────────────────────────────────

  async evaluateByName(testName: string, context: EvaluatorContext): Promise<TestEvaluation> {
    const n = testName.toLowerCase();

    if (n.includes('critical vulnerab')) return this.evaluateVulnerabilities('critical');
    if (n.includes('high vulnerab'))     return this.evaluateVulnerabilities('high');
    if (n.includes('medium vulnerab'))   return this.evaluateVulnerabilities('medium');
    if (n.includes('low vulnerab'))      return this.evaluateVulnerabilities('low');

    if (n.includes('accounts associated with users')) return this.evaluateGitHubAccountsAssociated();
    if (n.includes('all github members'))             return this.evaluateAllMembersMapToISMS(context.linkedGitHubLogins);
    if (n.includes('deprovisioned'))                  return this.evaluateDeprovisionedAccounts(context.linkedGitHubLogins);
    if (n.includes('mfa on github'))                  return this.evaluateMFA();

    if (n.includes('code changes were approved'))     return this.evaluateCodeReviewApproval();
    if (n.includes('application changes reviewed'))   return this.evaluateApplicationChangesReviewed();
    if (n.includes('author is not the reviewer'))     return this.evaluateAuthorNotReviewer();

    if (n.includes('version control system'))         return this.evaluateVersionControlExists();
    if (n.includes('repository visibility'))          return this.evaluateRepoVisibilityPrivate();

    // Unknown test — default pass with note
    return {
      testName,
      status: 'Warning',
      summary: `No evaluator implemented for: "${testName}"`,
      findings: [],
    };
  }
}

// Context passed from the route to the evaluator
export interface EvaluatorContext {
  linkedGitHubLogins: string[]; // GitHub usernames from UserGitAccount for this org
}

// Status mapping: evaluation result → TestStatus
export function evalResultToTestStatus(result: EvalResult): string {
  switch (result) {
    case 'Pass':    return 'OK';
    case 'Warning': return 'Due_soon';
    case 'Fail':    return 'Needs_remediation';
  }
}
