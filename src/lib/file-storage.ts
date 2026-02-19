/**
 * Local disk file storage utility.
 *
 * Files are saved to UPLOAD_DIR/<category>/<uuid>-<sanitised-filename>
 * and served publicly at  /files/<category>/<filename>  via @fastify/static.
 *
 * The returned `fileUrl` is an absolute URL (includes the API base) so that
 * the frontend can fetch/download it with a Bearer token by hitting
 * GET /api/files/:category/:filename  (authenticated proxy endpoint).
 */

import fs from 'fs';
import path from 'path';
import { pipeline } from 'stream/promises';
import { randomUUID } from 'crypto';
import { env } from '../config/env';

export const UPLOAD_DIR = path.resolve(env.UPLOAD_DIR);

/** Ensure a sub-directory exists under UPLOAD_DIR */
function ensureDir(subDir: string): string {
  const dir = path.join(UPLOAD_DIR, subDir);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Sanitise a filename — keep extension, strip dangerous characters */
function sanitiseName(original: string): string {
  const ext = path.extname(original).toLowerCase();
  const base = path.basename(original, ext)
    .replace(/[^a-zA-Z0-9_\-]/g, '_')
    .slice(0, 80);
  return `${base}${ext}`;
}

export type StoredFile = {
  /** Original filename from the upload */
  originalName: string;
  /** Saved filename on disk */
  savedName: string;
  /** Relative path from UPLOAD_DIR: "<category>/<savedName>" */
  relativePath: string;
  /** URL path at which the file is served: "/files/<category>/<savedName>" */
  fileUrl: string;
  /** MIME type */
  mimeType: string;
  /** File size in bytes */
  size: number;
};

/**
 * Save a multipart file stream to disk.
 *
 * @param fileField  The multipart file field object from @fastify/multipart
 * @param category   Sub-directory name, e.g. "policies" | "evidence"
 */
export async function saveUploadedFile(
  fileField: {
    filename: string;
    mimetype: string;
    file: NodeJS.ReadableStream;
  },
  category: 'policies' | 'evidence'
): Promise<StoredFile> {
  const sanitised = sanitiseName(fileField.filename);
  const savedName = `${randomUUID()}-${sanitised}`;
  const dir = ensureDir(category);
  const filePath = path.join(dir, savedName);

  const writeStream = fs.createWriteStream(filePath);
  await pipeline(fileField.file as any, writeStream);

  const { size } = fs.statSync(filePath);

  return {
    originalName: fileField.filename,
    savedName,
    relativePath: `${category}/${savedName}`,
    fileUrl: `/files/${category}/${savedName}`,
    mimeType: fileField.mimetype,
    size,
  };
}

/**
 * Delete a stored file given its relative path (e.g. "policies/uuid-name.pdf").
 * Silently ignores if file does not exist.
 */
export function deleteStoredFile(relativePath: string): void {
  try {
    const filePath = path.join(UPLOAD_DIR, relativePath);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {
    // ignore
  }
}

/**
 * Given a /files/<category>/<name> URL, return the absolute path on disk.
 * Returns null if the URL doesn't match the expected pattern.
 */
export function fileUrlToAbsPath(fileUrl: string): string | null {
  const match = fileUrl.match(/^\/files\/(.+)$/);
  if (!match || !match[1]) return null;
  return path.join(UPLOAD_DIR, match[1]);
}
