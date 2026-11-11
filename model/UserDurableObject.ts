import { DurableObject } from "cloudflare:workers";
import { ABSOLUTE_TTL_MS, JTI_WINDOW_MS, IDLE_TTL_MS, REFRESH_GRACE_MS } from "library/lib-be/constants";
import { sha256 } from "library/lib-be/security/conversions";
import { randomToken } from "library/lib-be/security/tokens";
import { uuidv4 } from "library/lib/security/uuid";
import { CreateSessionResult, RefreshResult, SessionInfo, VerifyResult } from "library/lib/types/authentication";
import { SessionRow } from "../types/security";

/**
 * One instance per user (idFromName(String(userId))).
 * Holds the user's sessions. Public methods are called over RPC from the Worker.
 *
 * Atomicity rule: do all `await`s (hashing, random generation) BEFORE the synchronous read-modify-write on SQLite.
 */
export class UserDurableObject extends DurableObject<Env> {
  private sql: SqlStorage;
  // In-memory on purpose: lost on eviction/restart, which only opens a short replay window.
  private seenJti = new Map<string, number>(); // <deviceId, jts>

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
				CREATE TABLE IF NOT EXISTS sessions (
					sid               TEXT PRIMARY KEY,
					jkt               TEXT NOT NULL,
					refresh_hash      TEXT NOT NULL,
					prev_refresh_hash TEXT,
					device_label      TEXT,
					created_at        INTEGER NOT NULL,
					last_seen         INTEGER NOT NULL,
					expires_abs       INTEGER NOT NULL
				);
			`);
    });
  }

  private getRow(sid: string): SessionRow | undefined {
    return this.sql.exec<SessionRow>(`SELECT * FROM sessions WHERE sid = ?`, sid).toArray()[0];
  }

  private isExpired(row: SessionRow, now: number): boolean {
    return row.expires_abs <= now || row.last_seen + IDLE_TTL_MS <= now;
  }

  private pruneJti(now: number): void {
    for (const [key, expiresAt] of this.seenJti) {
      if (expiresAt <= now) this.seenJti.delete(key);
    }
  }

  /** Remembers a proof id for JTI_WINDOW_MS. Returns false if it was already used. */
  private claimJti(key: string, now: number): boolean {
    this.pruneJti(now);
    if (this.seenJti.has(key)) return false;
    this.seenJti.set(key, now + JTI_WINDOW_MS);
    return true;
  }

  // SESSIONS

  async createSession(jkt: string, jti: string, deviceLabel?: string): Promise<CreateSessionResult> {
    // Called after the password was checked, so a replayed login proof is rejected here without a lookup before it.
    if (!this.claimJti(`login:${jti}`, Date.now())) return { ok: false, reason: "replay" };

    const sid = uuidv4();
    const refreshToken = randomToken();
    const refreshHash = await sha256(refreshToken);
    const now = Date.now();

    this.sql.exec(
      `INSERT INTO sessions (sid, jkt, refresh_hash, prev_refresh_hash, device_label, created_at, last_seen, expires_abs)
			 VALUES (?, ?, ?, NULL, ?, ?, ?, ?)`,
      sid, jkt, refreshHash, deviceLabel ?? null, now, now, now + ABSOLUTE_TTL_MS,
    );

    await this.scheduleCleanup();
    return { ok: true, sid, refreshToken };
  }

  async refresh(sid: string, presentedToken: string, jkt: string, jti: string): Promise<RefreshResult> {
    const presentedHash = await sha256(presentedToken);
    const newToken = randomToken();
    const newHash = await sha256(newToken);
    const now = Date.now();

    // synchronous section
    const row = this.getRow(sid);
    if (!row) return { ok: false, reason: "unknown_session" };
    if (row.jkt !== jkt) {
      // A real refresh token presented with another key: the token has been stolen, so end the session.
      // The user id and sid are not secret (the access token carries them), so only a caller who actually holds
      // the token may end the session this way. Otherwise anyone could log a user out with a made-up token.
      if (presentedHash === row.refresh_hash || presentedHash === row.prev_refresh_hash) {
        this.deleteSession(sid);
        return { ok: false, reason: "key_mismatch" };
      }
      return { ok: false, reason: "invalid_token" };
    }
    if (this.isExpired(row, now)) {
      this.deleteSession(sid);
      return { ok: false, reason: "expired" };
    }
    if (!this.claimJti(`${sid}:${jti}`, now)) return { ok: false, reason: "replay" };

    if (presentedHash === row.prev_refresh_hash) {
      // The previous token is tolerated briefly after a rotation: a page reloaded twice quickly, or two tabs,
      // present it before the browser has received the rotated one. Rotate again and carry on.
      // Later than that, an already-rotated token coming back means theft: kill the session.
      if (now - row.last_seen > REFRESH_GRACE_MS) {
        this.deleteSession(sid);
        return { ok: false, reason: "reuse_detected" };
      }
    } else if (presentedHash !== row.refresh_hash) {
      return { ok: false, reason: "invalid_token" };
    }

    this.sql.exec(
      `UPDATE sessions SET prev_refresh_hash = refresh_hash, refresh_hash = ?, last_seen = ? WHERE sid = ?`,
      newHash, now, sid,
    );
    return { ok: true, sid, refreshToken: newToken };
  }

  private deleteSession(sid: string): boolean {
    const cursor = this.sql.exec(`DELETE FROM sessions WHERE sid = ?`, sid);
    return cursor.rowsWritten > 0;
  }

  /**
   * Check that a session is alive and bound to this key.
   * Pass `jti` to also enforce single-use proofs (sensitive endpoints).
   */
  async verify(sid: string, jkt: string, jti?: string): Promise<VerifyResult> {
    const now = Date.now();
    const row = this.getRow(sid);
    if (!row) return { ok: false, reason: "unknown_session" };
    if (row.jkt !== jkt) return { ok: false, reason: "key_mismatch" };
    if (this.isExpired(row, now)) {
      this.deleteSession(sid);
      return { ok: false, reason: "expired" };
    }

    if (jti) {
      if (!this.claimJti(`${sid}:${jti}`, now)) return { ok: false, reason: "replay" };
    }
    return { ok: true };
  }

  async revoke(sid: string): Promise<boolean> {
    return this.deleteSession(sid);
  }

  async revokeAll(): Promise<void> {
    this.sql.exec(`DELETE FROM sessions`);
    this.seenJti.clear();
  }

  async listSessions(): Promise<SessionInfo[]> {
    return this.sql
      .exec<SessionRow>(`SELECT * FROM sessions ORDER BY last_seen DESC`)
      .toArray()
      .map((r) => ({
        sid: r.sid,
        jkt: r.jkt,
        deviceLabel: r.device_label,
        createdAt: r.created_at,
        lastSeen: r.last_seen,
      }));
  }

  // Session cleanup

  async alarm(): Promise<void> {
    const now = Date.now();
    this.sql.exec(`DELETE FROM sessions WHERE expires_abs <= ? OR last_seen + ? <= ?`, now, IDLE_TTL_MS, now);
    await this.scheduleCleanup();
  }

  private async scheduleCleanup(): Promise<void> {
    const next = this.sql
      .exec<{ t: number | null }>(`SELECT MIN(MIN(expires_abs, last_seen + ?)) AS t FROM sessions`, IDLE_TTL_MS)
      .one().t;
    if (next === null) return; // no sessions left, nothing to schedule
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > next) await this.ctx.storage.setAlarm(next);
  }
}
