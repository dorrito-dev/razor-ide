// Pure Node.js ZIP archive writer with zero dependencies.
// Creates standard PKZIP archives compatible with Windows Explorer,
// PowerShell Expand-Archive, unzip, 7-Zip, etc.
import { deflateRawSync } from 'node:zlib';

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[n] = c;
}

export function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Build a ZIP archive buffer from an array of files.
 * @param {Array<{ name: string, data: Buffer|string, isDir?: boolean }>} files
 * @returns {Buffer}
 */
export function createZip(files) {
  const localChunks = [];
  const centralEntries = [];
  let offset = 0;

  for (const file of files) {
    const isDir = Boolean(file.isDir);
    const rawData = Buffer.isBuffer(file.data)
      ? file.data
      : Buffer.from(file.data ?? '', 'utf8');
    const nameStr = file.name.replace(/\\/g, '/');
    const nameBytes = Buffer.from(nameStr, 'utf8');

    let compressedData = rawData;
    let method = 0; // 0 = STORE (uncompressed)
    if (!isDir && rawData.length > 0) {
      try {
        const deflated = deflateRawSync(rawData);
        if (deflated.length < rawData.length) {
          compressedData = deflated;
          method = 8; // 8 = DEFLATE
        }
      } catch {
        compressedData = rawData;
        method = 0;
      }
    }

    const fileCrc = crc32(rawData);
    const uncompressedSize = rawData.length;
    const compressedSize = compressedData.length;

    // Local file header (30 bytes + name)
    const localHeader = Buffer.alloc(30 + nameBytes.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // local file header signature
    localHeader.writeUInt16LE(20, 4);         // version needed to extract (2.0)
    localHeader.writeUInt16LE(0x0800, 6);     // general purpose bit flag (UTF-8)
    localHeader.writeUInt16LE(method, 8);     // compression method
    localHeader.writeUInt16LE(0, 10);         // last mod file time
    localHeader.writeUInt16LE(0, 12);         // last mod file date
    localHeader.writeUInt32LE(fileCrc, 14);    // crc-32
    localHeader.writeUInt32LE(compressedSize, 18);   // compressed size
    localHeader.writeUInt32LE(uncompressedSize, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBytes.length, 26); // file name length
    localHeader.writeUInt16LE(0, 28);         // extra field length
    nameBytes.copy(localHeader, 30);

    const chunk = Buffer.concat([localHeader, compressedData]);
    localChunks.push(chunk);

    // Central directory header (46 bytes + name)
    const centralHeader = Buffer.alloc(46 + nameBytes.length);
    centralHeader.writeUInt32LE(0x02014b50, 0); // central file header signature
    centralHeader.writeUInt16LE(20, 4);          // version made by
    centralHeader.writeUInt16LE(20, 6);          // version needed to extract
    centralHeader.writeUInt16LE(0x0800, 8);      // general purpose bit flag (UTF-8)
    centralHeader.writeUInt16LE(method, 10);     // compression method
    centralHeader.writeUInt16LE(0, 12);          // last mod file time
    centralHeader.writeUInt16LE(0, 14);          // last mod file date
    centralHeader.writeUInt32LE(fileCrc, 16);     // crc-32
    centralHeader.writeUInt32LE(compressedSize, 20);   // compressed size
    centralHeader.writeUInt32LE(uncompressedSize, 24); // uncompressed size
    centralHeader.writeUInt16LE(nameBytes.length, 28); // file name length
    centralHeader.writeUInt16LE(0, 30);          // extra field length
    centralHeader.writeUInt16LE(0, 32);          // file comment length
    centralHeader.writeUInt16LE(0, 34);          // disk number start
    centralHeader.writeUInt16LE(0, 36);          // internal file attributes
    centralHeader.writeUInt32LE(isDir ? 0x10 : 0x20, 38); // external file attributes
    centralHeader.writeUInt32LE(offset, 42);     // relative offset of local header
    nameBytes.copy(centralHeader, 46);

    centralEntries.push(centralHeader);
    offset += chunk.length;
  }

  const centralDirData = Buffer.concat(centralEntries);
  const centralDirOffset = offset;
  const centralDirSize = centralDirData.length;

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // end of central dir signature
  eocd.writeUInt16LE(0, 4);          // number of this disk
  eocd.writeUInt16LE(0, 6);          // number of the disk with the start of the central directory
  eocd.writeUInt16LE(files.length, 8);  // total number of entries in the central directory on this disk
  eocd.writeUInt16LE(files.length, 10); // total number of entries in the central directory
  eocd.writeUInt32LE(centralDirSize, 12);    // size of the central directory
  eocd.writeUInt32LE(centralDirOffset, 16);  // offset of start of central directory
  eocd.writeUInt16LE(0, 20);         // .ZIP file comment length

  return Buffer.concat([...localChunks, centralDirData, eocd]);
}
