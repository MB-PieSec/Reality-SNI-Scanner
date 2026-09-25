/**
 * Minimal ZIP reader, just enough to pull one file out of an official
 * Xray-core release archive.
 *
 * Why hand-rolled: Stage 2 ships Xray-core inside the project, and the tool's
 * whole selling point is "no npm install, no extra software". Node has zlib
 * (which is all an inflated ZIP entry needs) but no ZIP parser, so reading the
 * central directory ourselves keeps the dependency count at zero.
 */

import zlib from "node:zlib";

const EOCD_SIGNATURE = 0x06054b50; // end of central directory record
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const EOCD_MIN_SIZE = 22;
const MAX_COMMENT_BYTES = 0xffff;

function findEndOfCentralDirectory(zip: Buffer): number {
  const earliest = Math.max(0, zip.length - (EOCD_MIN_SIZE + MAX_COMMENT_BYTES));
  for (let i = zip.length - EOCD_MIN_SIZE; i >= earliest; i--) {
    if (zip.readUInt32LE(i) === EOCD_SIGNATURE) return i;
  }
  throw new Error("not a ZIP archive (end-of-central-directory record not found)");
}

/** Returns the uncompressed bytes of `entryName` inside `zip`. */
export function extractZipEntry(zip: Buffer, entryName: string): Buffer {
  const eocd = findEndOfCentralDirectory(zip);
  const entryCount = zip.readUInt16LE(eocd + 10);
  const centralDirOffset = zip.readUInt32LE(eocd + 16);
  if (entryCount === 0xffff || centralDirOffset === 0xffffffff) {
    throw new Error("ZIP64 archives are not supported");
  }

  // Walk the central directory: it is the only place that has trustworthy
  // sizes, because entries may carry a "data descriptor" after their local
  // header (which leaves the local sizes as zero).
  let offset = centralDirOffset;
  for (let i = 0; i < entryCount; i++) {
    if (zip.readUInt32LE(offset) !== CENTRAL_DIR_SIGNATURE) {
      throw new Error("corrupt ZIP: bad central directory entry");
    }
    const method = zip.readUInt16LE(offset + 10);
    const compressedSize = zip.readUInt32LE(offset + 20);
    const nameLength = zip.readUInt16LE(offset + 28);
    const extraLength = zip.readUInt16LE(offset + 30);
    const commentLength = zip.readUInt16LE(offset + 32);
    const localOffset = zip.readUInt32LE(offset + 42);
    const name = zip.toString("utf8", offset + 46, offset + 46 + nameLength);

    if (name === entryName) return readEntry(zip, localOffset, method, compressedSize);

    offset += 46 + nameLength + extraLength + commentLength;
  }

  throw new Error(`ZIP: entry not found: ${entryName}`);
}

function readEntry(zip: Buffer, localOffset: number, method: number, compressedSize: number): Buffer {
  if (localOffset + 30 > zip.length || zip.readUInt32LE(localOffset) !== LOCAL_HEADER_SIGNATURE) {
    throw new Error("corrupt ZIP: bad local header");
  }
  const nameLength = zip.readUInt16LE(localOffset + 26);
  const extraLength = zip.readUInt16LE(localOffset + 28);
  const start = localOffset + 30 + nameLength + extraLength;
  const end = start + compressedSize;
  if (end > zip.length) throw new Error("corrupt ZIP: entry is truncated");

  const raw = zip.subarray(start, end);
  if (method === 0) return Buffer.from(raw); // stored
  if (method === 8) return zlib.inflateRawSync(raw); // deflate
  throw new Error(`ZIP: unsupported compression method ${method}`);
}
