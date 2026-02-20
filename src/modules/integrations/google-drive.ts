/**
 * Google Drive integration helper.
 *
 * Responsibilities:
 *  - Build the OAuth 2.0 authorization URL (drive.file scope)
 *  - Exchange auth code → tokens
 *  - Auto-refresh an access token when it is about to expire
 *  - Bootstrap the ISMS folder structure in Drive:
 *      ISMS-{OrgName}/
 *        Evidence/
 *        Policies/
 *  - Upload a file stream to a given Drive folder; return the public-viewable URL
 */

import { google } from 'googleapis';
import { Readable } from 'stream';
import { env } from '../../config/env';
import { encrypt, decrypt } from '../../lib/crypto';
import { prisma } from '../../lib/prisma';

// ─── OAuth2 client factory ────────────────────────────────────────────────────

function makeOAuthClient() {
  return new google.auth.OAuth2(
    env.GOOGLE_DRIVE_CLIENT_ID,
    env.GOOGLE_DRIVE_CLIENT_SECRET,
    env.GOOGLE_DRIVE_CALLBACK_URL,
  );
}

// ─── Public helpers ───────────────────────────────────────────────────────────

/**
 * Return the Google OAuth consent-screen URL for Drive access.
 * We encode `orgId` + `userId` in the `state` param so the callback
 * knows whose integration to update.
 */
export function getDriveAuthUrl(orgId: string, userId: string): string {
  const oauth2Client = makeOAuthClient();
  const state = Buffer.from(JSON.stringify({ orgId, userId })).toString('base64url');
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
    prompt: 'consent', // force refresh_token to be returned even if previously granted
    state,
  });
}

export interface DriveTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}

/**
 * Exchange an authorization code for tokens.
 */
export async function exchangeCodeForTokens(code: string): Promise<DriveTokens> {
  const oauth2Client = makeOAuthClient();
  const { tokens } = await oauth2Client.getToken(code);

  if (!tokens.access_token || !tokens.refresh_token) {
    throw new Error('Google did not return required tokens');
  }

  const expiresAt = tokens.expiry_date
    ? new Date(tokens.expiry_date)
    : new Date(Date.now() + 3600 * 1000);

  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt,
  };
}

/**
 * Get a ready-to-use OAuth2 client for a given org, refreshing if needed.
 * Updates the DB record when a token refresh happens.
 */
async function getAuthedClient(organizationId: string) {
  const integration = await prisma.integration.findUnique({
    where: { organizationId_provider: { organizationId, provider: 'GOOGLE_DRIVE' } },
  });

  if (!integration || integration.status !== 'ACTIVE') {
    throw new Error('Google Drive not connected for this organisation');
  }

  const oauth2Client = makeOAuthClient();
  const accessToken = decrypt(integration.accessToken);
  const refreshToken = integration.refreshToken ? decrypt(integration.refreshToken) : undefined;

  oauth2Client.setCredentials({
    access_token: accessToken,
    refresh_token: refreshToken,
    expiry_date: integration.expiresAt ? integration.expiresAt.getTime() : undefined,
  });

  // If token expires within 5 minutes, force a refresh now
  const bufferMs = 5 * 60 * 1000;
  const needsRefresh =
    !integration.expiresAt || integration.expiresAt.getTime() - Date.now() < bufferMs;

  if (needsRefresh && refreshToken) {
    const { credentials } = await oauth2Client.refreshAccessToken();
    const newExpiry = credentials.expiry_date
      ? new Date(credentials.expiry_date)
      : new Date(Date.now() + 3600 * 1000);

    await prisma.integration.update({
      where: { id: integration.id },
      data: {
        accessToken: encrypt(credentials.access_token!),
        expiresAt: newExpiry,
      },
    });

    oauth2Client.setCredentials(credentials);
  }

  return { oauth2Client, integration };
}

// ─── Folder helpers ───────────────────────────────────────────────────────────

async function findOrCreateFolder(
  drive: ReturnType<typeof google.drive>,
  name: string,
  parentId?: string,
): Promise<string> {
  const q = [
    `name = '${name.replace(/'/g, "\\'")}'`,
    `mimeType = 'application/vnd.google-apps.folder'`,
    `trashed = false`,
    parentId ? `'${parentId}' in parents` : '',
  ]
    .filter(Boolean)
    .join(' and ');

  const { data } = await drive.files.list({
    q,
    fields: 'files(id, name)',
    spaces: 'drive',
  });

  const firstFile = data.files?.[0];
  if (firstFile?.id) {
    return firstFile.id;
  }

  const createRes = await drive.files.create({
    requestBody: {
      name,
      mimeType: 'application/vnd.google-apps.folder',
      ...(parentId ? { parents: [parentId] } : {}),
    },
    fields: 'id',
  });

  return createRes.data.id!;
}

export interface DriveFolderIds {
  rootFolderId: string;
  evidenceFolderId: string;
  policyFolderId: string;
}

/**
 * Ensure the folder structure exists in Drive:
 *   ISMS-{OrgName}/Evidence/
 *   ISMS-{OrgName}/Policies/
 * Returns folder IDs and persists them to `integration.metadata`.
 */
export async function bootstrapFolderStructure(
  organizationId: string,
  orgName: string,
): Promise<DriveFolderIds> {
  const { oauth2Client, integration } = await getAuthedClient(organizationId);
  const drive = google.drive({ version: 'v3', auth: oauth2Client });

  const rootFolderId = await findOrCreateFolder(drive, `ISMS-${orgName}`);
  const evidenceFolderId = await findOrCreateFolder(drive, 'Evidence', rootFolderId);
  const policyFolderId = await findOrCreateFolder(drive, 'Policies', rootFolderId);

  // Persist folder IDs in integration.metadata
  await prisma.integration.update({
    where: { id: integration.id },
    data: {
      metadata: { rootFolderId, evidenceFolderId, policyFolderId } as any,
    },
  });

  return { rootFolderId, evidenceFolderId, policyFolderId };
}

// ─── File upload ──────────────────────────────────────────────────────────────

export interface DriveUploadResult {
  driveFileId: string;
  webViewLink: string;
  name: string;
}

/**
 * Upload a file to a specific Drive folder.
 * Returns the Drive file ID and a web-viewable URL.
 */
export async function uploadFileToDrive(
  organizationId: string,
  fileStream: Readable,
  fileName: string,
  mimeType: string,
  folderId: string,
): Promise<DriveUploadResult> {
  const { oauth2Client } = await getAuthedClient(organizationId);
  const drive = google.drive({ version: 'v3', auth: oauth2Client });

  const res = await drive.files.create({
    requestBody: {
      name: fileName,
      parents: [folderId],
    },
    media: {
      mimeType,
      body: fileStream,
    },
    fields: 'id, webViewLink, name',
  });

  return {
    driveFileId: res.data.id!,
    webViewLink: res.data.webViewLink!,
    name: res.data.name!,
  };
}

/**
 * Get the Drive folder IDs stored in integration.metadata for an org.
 * Returns null if Drive is not connected or folders haven't been bootstrapped yet.
 */
export async function getDriveFolderIds(
  organizationId: string,
): Promise<DriveFolderIds | null> {
  const integration = await prisma.integration.findUnique({
    where: { organizationId_provider: { organizationId, provider: 'GOOGLE_DRIVE' } },
  });

  if (!integration || integration.status !== 'ACTIVE' || !integration.metadata) return null;

  const meta = integration.metadata as any;
  if (!meta.evidenceFolderId || !meta.policyFolderId) return null;

  return {
    rootFolderId: meta.rootFolderId,
    evidenceFolderId: meta.evidenceFolderId,
    policyFolderId: meta.policyFolderId,
  };
}
