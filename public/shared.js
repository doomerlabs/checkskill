export const maxPackageBytes = 10 * 1024 * 1024;
export const maxSkillBytes = maxPackageBytes;
export const maxHighlightedSourceBytes = 64 * 1024;
export const maxPackageFiles = 384;
export const packageSizeLabel = '10 MiB';
export const maxPathLength = 256;
const maxShareCharacters = 24000;
const maxLegacyShareBytes = 64 * 1024;

export async function decodeShare(fragment) {
  const prefix = '#skill=v1.';
  if (!fragment.startsWith(prefix)) throw new Error('This share link uses an unsupported format.');
  const encoded = fragment.slice(prefix.length);
  if (!encoded || encoded.length > maxShareCharacters || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error('This share link is invalid or too large.');
  }

  const binary = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let size = 0;
  let skill = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxLegacyShareBytes) throw new Error('This share link expands beyond the 64 KiB skill limit.');
      skill += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  skill += decoder.decode();
  if (!skill.trim()) throw new Error('This share link contains an empty skill.');
  return skill;
}
