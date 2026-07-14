// Random overlay range generation for the network editor.
//
// The IPv4 draw pools are deliberately narrower than "all private
// space":
//
//   10.0.0.0/8     -> 10.R.0.0/16          (256 candidate ranges)
//   100.64.0.0/10  -> 100.(64+R).0.0/16    (64 candidates; CGNAT space,
//                     the Tailscale-style pool, never routed on LANs)
//
// 172.16.0.0/12 and 192.168.0.0/16 are excluded entirely: Docker's
// default address pools mint bridge subnets from both (and 192.168 is
// every home LAN), so a random overlay inside them is a collision
// waiting to happen on any docker-sidecar'd agent host. They are still
// listed in builtinAvoid4 as defense in depth should the pools above
// ever widen.
//
// IPv6 draws an RFC 4193 ULA /64: fd + 40 random global-ID bits + 16
// random subnet bits. Randomness comes from crypto.getRandomValues, as
// RFC 4193 asks, which also makes cross-organization collisions
// practically impossible.

const builtinAvoid4 = ["172.16.0.0/12", "192.168.0.0/16"];

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

type V4Prefix = { base: number; bits: number };

function parseV4Prefix(cidr: string): V4Prefix | null {
  const m = cidr.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  const bits = Number(m[5]);
  if (octets.some((o) => o > 255) || bits > 32) return null;
  const base = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  return { base, bits };
}

function v4Overlap(a: V4Prefix, b: V4Prefix): boolean {
  const bits = Math.min(a.bits, b.bits);
  if (bits === 0) return true;
  const shift = 32 - bits;
  return a.base >>> shift === b.base >>> shift;
}

// randomOverlayV4 returns a random private /16 that overlaps neither
// the avoid list (current/typed ranges) nor Docker's default pools.
export function randomOverlayV4(avoid: string[]): string {
  const avoidPrefixes = [...avoid, ...builtinAvoid4]
    .map(parseV4Prefix)
    .filter((p): p is V4Prefix => p !== null);

  for (let attempt = 0; attempt < 64; attempt++) {
    const [poolPick, r] = randomBytes(2);
    const candidate =
      poolPick % 2 === 0 ? `10.${r}.0.0/16` : `100.${64 + (r % 64)}.0.0/16`;

    const parsed = parseV4Prefix(candidate);
    if (parsed && !avoidPrefixes.some((p) => v4Overlap(parsed, p))) return candidate;
  }

  throw new Error("could not find a free random IPv4 range");
}

type V6Prefix = { base: bigint; bits: number };

// parseV6Prefix handles the canonical forms this feature meets
// (grouped hex with at most one "::"); anything it cannot parse is
// skipped rather than blocking generation — the server revalidates.
function parseV6Prefix(cidr: string): V6Prefix | null {
  const m = cidr.trim().toLowerCase().match(/^([0-9a-f:]+)\/(\d{1,3})$/);
  if (!m || Number(m[2]) > 128) return null;

  const halves = m[1].split("::");
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - left.length - right.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;

  const groups = [...left, ...Array(fill).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((g) => g.length === 0 || g.length > 4)) return null;

  let base = 0n;
  for (const g of groups) base = (base << 16n) | BigInt(parseInt(g, 16));
  return { base, bits: Number(m[2]) };
}

function v6Overlap(a: V6Prefix, b: V6Prefix): boolean {
  const bits = Math.min(a.bits, b.bits);
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return a.base >> shift === b.base >> shift;
}

// randomOverlayV6 returns a random RFC 4193 ULA /64.
export function randomOverlayV6(avoid: string[]): string {
  const avoidPrefixes = avoid
    .map(parseV6Prefix)
    .filter((p): p is V6Prefix => p !== null);

  for (let attempt = 0; attempt < 64; attempt++) {
    const b = randomBytes(7); // 40-bit global ID + 16-bit subnet
    const hex = (i: number) => ((b[i] << 8) | b[i + 1]).toString(16);
    const candidate = `fd${b[0].toString(16).padStart(2, "0")}:${hex(1)}:${hex(3)}:${hex(5)}::/64`;

    const parsed = parseV6Prefix(candidate);
    if (parsed && !avoidPrefixes.some((p) => v6Overlap(parsed, p))) return candidate;
  }

  throw new Error("could not find a free random IPv6 range");
}
