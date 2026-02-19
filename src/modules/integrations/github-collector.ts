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

function sha256(data: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

// ─── Repository list ─────────────────────────────────────────────────────────

export async function fetchRepos(token: string) {
  const repos: any[] = [];
  let page = 1;
  while (true) {
    const { data } = await axios.get(`${GH_API}/user/repos`, {
      headers: ghHeaders(token),
      params: { per_page: 100, page, sort: 'updated' },
    });
    repos.push(...data);
    if (data.length < 100) break;
    page++;
  }
  return repos;
}

// ─── Branch Protection (A.8.32) ──────────────────────────────────────────────

export async function collectBranchProtection(token: string, owner: string, repo: string, branch: string) {
  try {
    const { data } = await axios.get(
      `${GH_API}/repos/${owner}/${repo}/branches/${branch}/protection`,
      { headers: ghHeaders(token) }
    );

    const result = {
      controlRef: 'A.8.32',
      title: 'Branch Protection',
      repo: `${owner}/${repo}`,
      branch,
      requiredReviews: data.required_pull_request_reviews?.required_approving_review_count ?? 0,
      dismissStaleReviews: data.required_pull_request_reviews?.dismiss_stale_reviews ?? false,
      requireStatusChecks: !!data.required_status_checks,
      allowForcePushes: data.allow_force_pushes?.enabled ?? true,
      enforceAdmins: data.enforce_admins?.enabled ?? false,
      compliant:
        (data.required_pull_request_reviews?.required_approving_review_count ?? 0) >= 1 &&
        !(data.allow_force_pushes?.enabled ?? true) &&
        !!data.required_status_checks,
      raw: data,
    };
    return { result, hash: sha256(result) };
  } catch (err: any) {
    if (err.response?.status === 404) {
      // Branch protection not configured
      const result = {
        controlRef: 'A.8.32',
        title: 'Branch Protection',
        repo: `${owner}/${repo}`,
        branch,
        compliant: false,
        reason: 'No branch protection configured',
      };
      return { result, hash: sha256(result) };
    }
    throw err;
  }
}

// ─── Commit Signing (A.8.24) ─────────────────────────────────────────────────

export async function collectCommitSigning(token: string, owner: string, repo: string) {
  const { data: commits } = await axios.get(`${GH_API}/repos/${owner}/${repo}/commits`, {
    headers: ghHeaders(token),
    params: { per_page: 20 },
  });

  const signed = commits.filter((c: any) => c.commit?.verification?.verified).length;
  const result = {
    controlRef: 'A.8.24',
    title: 'Commit Signing',
    repo: `${owner}/${repo}`,
    totalChecked: commits.length,
    signedCount: signed,
    signedPercent: commits.length ? Math.round((signed / commits.length) * 100) : 0,
    compliant: commits.length > 0 && signed / commits.length >= 0.8,
  };
  return { result, hash: sha256(result) };
}

// ─── CI/CD Presence (A.8.25) ─────────────────────────────────────────────────

export async function collectCICD(token: string, owner: string, repo: string) {
  try {
    const { data } = await axios.get(`${GH_API}/repos/${owner}/${repo}/actions/workflows`, {
      headers: ghHeaders(token),
    });
    const result = {
      controlRef: 'A.8.25',
      title: 'Secure SDLC / CI-CD Presence',
      repo: `${owner}/${repo}`,
      workflowCount: data.total_count,
      workflows: (data.workflows ?? []).map((w: any) => ({ name: w.name, state: w.state })),
      compliant: data.total_count > 0,
    };
    return { result, hash: sha256(result) };
  } catch {
    const result = {
      controlRef: 'A.8.25',
      title: 'Secure SDLC / CI-CD Presence',
      repo: `${owner}/${repo}`,
      workflowCount: 0,
      compliant: false,
    };
    return { result, hash: sha256(result) };
  }
}

// ─── Access Control / Collaborators (A.5.15) ─────────────────────────────────

export async function collectAccessControl(token: string, owner: string, repo: string) {
  try {
    const { data: collaborators } = await axios.get(
      `${GH_API}/repos/${owner}/${repo}/collaborators`,
      {
        headers: ghHeaders(token),
        params: { per_page: 100, affiliation: 'all' },
      }
    );

    const admins = collaborators.filter((c: any) => c.permissions?.admin);
    const external = collaborators.filter((c: any) => c.role_name === 'outside_collaborator');

    const result = {
      controlRef: 'A.5.15',
      title: 'Access Control - Collaborators',
      repo: `${owner}/${repo}`,
      totalCollaborators: collaborators.length,
      adminCount: admins.length,
      externalCount: external.length,
      admins: admins.map((c: any) => c.login),
      compliant: external.length === 0 && admins.length <= 3,
    };
    return { result, hash: sha256(result) };
  } catch {
    const result = {
      controlRef: 'A.5.15',
      title: 'Access Control - Collaborators',
      repo: `${owner}/${repo}`,
      compliant: null,
      reason: 'Insufficient permissions to list collaborators',
    };
    return { result, hash: sha256(result) };
  }
}

// ─── Default Branch / Visibility (A.5.15) ────────────────────────────────────

export function collectRepoMeta(repo: any) {
  const result = {
    controlRef: 'A.5.15',
    title: 'Repository Visibility & Access',
    repo: repo.full_name,
    defaultBranch: repo.default_branch,
    visibility: repo.visibility,
    private: repo.private,
    compliant: repo.private === true,
  };
  return { result, hash: sha256(result) };
}

// ─── Full scan for one repo ───────────────────────────────────────────────────

export async function scanRepo(token: string, repo: any) {
  const [owner, name] = repo.full_name.split('/');
  const checks = await Promise.allSettled([
    collectBranchProtection(token, owner, name, repo.default_branch),
    collectCommitSigning(token, owner, name),
    collectCICD(token, owner, name),
    collectAccessControl(token, owner, name),
  ]);

  return {
    repoMeta: collectRepoMeta(repo),
    branchProtection: checks[0].status === 'fulfilled' ? checks[0].value : null,
    commitSigning: checks[1].status === 'fulfilled' ? checks[1].value : null,
    cicd: checks[2].status === 'fulfilled' ? checks[2].value : null,
    accessControl: checks[3].status === 'fulfilled' ? checks[3].value : null,
    scannedAt: new Date().toISOString(),
  };
}
