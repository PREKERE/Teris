import { cookies } from "next/headers";
import { createHmac, timingSafeEqual } from "node:crypto";
const COOKIE = "purple_arcade_session";
function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) throw new Error("SESSION_SECRET harus diisi minimal 32 karakter.");
  return s;
}
export function signSession(user: { id: string; role: string }) {
  const payload = Buffer.from(JSON.stringify({ ...user, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 })).toString("base64url");
  const sig = createHmac("sha256", secret()).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
export function verifySession(token: string | undefined) {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = createHmac("sha256", secret()).update(payload).digest();
  let actual: Buffer;
  try { actual = Buffer.from(sig, "base64url"); } catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (data.exp < Date.now() || typeof data.id !== "string") return null;
    return { id: data.id as string, role: data.role as string };
  } catch { return null; }
}
export async function currentUser() {
  const jar = await cookies();
  const session = verifySession(jar.get(COOKIE)?.value);
  if (!session) return null;
  const { prisma } = await import("@/lib/prisma");
  const user = await prisma.user.findUnique({ where: { id: session.id }, select: { id: true, username: true, email: true, role: true, coins: true } });
  return user;
}
export const sessionCookieName = COOKIE;
