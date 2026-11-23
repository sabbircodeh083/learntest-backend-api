import { describe, it, expect } from "vitest";
import bcrypt from "bcrypt";
import { assertSignupRole, signupRoleState, withVerificationRedirect } from "../src/auth/auth.js";
import { env, corsOrigins, trustedOrigins } from "../src/config/env.js";
import { evaluateValidation, canTransition } from "../src/modules/payments/payment-state.js";
import { mimeMatchesExt, kindOfMime, PURPOSE_RULES, detectFileType } from "../src/modules/uploads.routes.js";
import { formatZodError } from "../src/common/middleware.js";
import { contentBody, httpUrl } from "../src/common/schemas.js";
import { z } from "zod";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const order = { tranId: "LT-1", amount: 500, currency: "BDT" };
const valid = { status: "VALID", tran_id: "LT-1", amount: "500.00", currency: "BDT", risk_level: "0", val_id: "v1" };

describe("bcrypt via Better Auth callbacks contract (§19.1)", () => {
  it("hashes (never plaintext) and verifies correct/incorrect passwords", async () => {
    const hash = await bcrypt.hash("correct horse", 12);
    expect(hash).not.toContain("correct horse");
    expect(hash.startsWith("$2")).toBe(true);
    await expect(bcrypt.compare("correct horse", hash)).resolves.toBe(true);
    await expect(bcrypt.compare("wrong", hash)).resolves.toBe(false);
  });
});

describe("trusted origins", () => {
  it("always includes the configured frontend origin for CORS and Better Auth", () => {
    const frontend = new URL(env.FRONTEND_URL).origin;
    expect(corsOrigins).toContain(frontend);
    expect(trustedOrigins).toContain(frontend);
  });

  it("trusts every CORS origin for Better Auth callbacks too", () => {
    for (const origin of corsOrigins) expect(trustedOrigins).toContain(origin);
  });

  it("normalizes origins to scheme + host + port", () => {
    for (const origin of [...corsOrigins, ...trustedOrigins]) {
      expect(origin).not.toBe("");
      expect(origin.endsWith("/")).toBe(false);
    }
  });
});

describe("email verification redirect", () => {
  const link = (callback: string) =>
    `https://api.example.com/api/auth/verify-email?token=t&callbackURL=${encodeURIComponent(callback)}`;

  it("replaces Better Auth's default '/' callback with the sign-in page", () => {
    for (const callback of ["/", ""]) {
      const parsed = new URL(withVerificationRedirect(link(callback)));
      const redirect = parsed.searchParams.get("callbackURL") ?? "";
      expect(redirect).not.toBe("/");
      expect(redirect).toMatch(/\/sign-in\?verified=1$/);
    }
  });

  it("keeps a client-supplied callback (e.g. the change-email flow)", () => {
    const custom = "https://www.easylearntest.tech/settings";
    const parsed = new URL(withVerificationRedirect(link(custom)));
    expect(parsed.searchParams.get("callbackURL")).toBe(custom);
  });

  it("returns malformed URLs untouched", () => {
    expect(withVerificationRedirect("not a url")).toBe("not a url");
  });
});

describe("role-based signup (§19.2)", () => {
  it("allows student/teacher, leaves empty undefined (OAuth/no-role)", () => {
    expect(assertSignupRole("student")).toBe("student");
    expect(assertSignupRole("teacher")).toBe("teacher");
    expect(assertSignupRole(undefined)).toBeUndefined();
  });
  it("rejects admin and any other role at public signup", () => {
    expect(() => assertSignupRole("admin")).toThrow();
    expect(() => assertSignupRole("superuser")).toThrow();
  });
  it("marks role onboarding complete when a signup role was supplied", () => {
    expect(signupRoleState("student")).toEqual({ role: "student", roleSelected: true });
    expect(signupRoleState("teacher")).toEqual({ role: "teacher", roleSelected: true });
  });
  it("leaves OAuth/no-role signups unselected for /select-role", () => {
    expect(signupRoleState(undefined)).toEqual({ role: undefined, roleSelected: false });
    expect(signupRoleState("")).toEqual({ role: undefined, roleSelected: false });
  });
});

describe("payment validation state machine (§7, §15)", () => {
  it("verified VALID with matching tran/amount/currency pays", () => {
    expect(evaluateValidation(order, valid).decision).toBe("paid");
    expect(evaluateValidation(order, { ...valid, status: "VALIDATED" }).decision).toBe("paid");
  });
  it("fake success without validation fields never pays", () => {
    expect(evaluateValidation(order, { status: "SUCCESS" }).decision).not.toBe("paid");
    expect(evaluateValidation(order, {}).decision).not.toBe("paid");
    expect(evaluateValidation(order, null as any).decision).toBe("rejected");
  });
  it("wrong amount / order / currency is rejected", () => {
    expect(evaluateValidation(order, { ...valid, amount: "1" }).decision).toBe("rejected");
    expect(evaluateValidation(order, { ...valid, tran_id: "OTHER" }).decision).toBe("rejected");
    expect(evaluateValidation(order, { ...valid, currency: "USD" }).decision).toBe("rejected");
  });
  it("risk_level=1 is held, FAILED/CANCELLED/EXPIRED map explicitly", () => {
    expect(evaluateValidation(order, { ...valid, risk_level: "1" }).decision).toBe("risk_hold");
    expect(evaluateValidation(order, { status: "FAILED" }).decision).toBe("failed");
    expect(evaluateValidation(order, { status: "CANCELLED" }).decision).toBe("cancelled");
    expect(evaluateValidation(order, { status: "EXPIRED" }).decision).toBe("expired");
    expect(evaluateValidation(order, { status: "UNATTEMPTED" }).decision).toBe("pending");
  });
  it("transitions are controlled and idempotent (paid is terminal)", () => {
    expect(canTransition("pending", "paid")).toBe(true);
    expect(canTransition("paid", "paid")).toBe(true); // duplicate IPN = no-op
    expect(canTransition("paid", "failed")).toBe(false);
    expect(canTransition("failed", "paid")).toBe(false);
  });
});

describe("validation error messages", () => {
  it("names the offending field and rule instead of a generic message", () => {
    const r = contentBody.safeParse({ title: "", price: -5, currency: "EUR" });
    expect(r.success).toBe(false);
    if (!r.success) {
      const msg = formatZodError(r.error);
      expect(msg).toContain("title");
      expect(msg).toContain("price");
      expect(msg).toContain("currency");
      expect(msg).not.toBe("Invalid input");
    }
  });
});

describe("httpUrl schema (profile socials)", () => {
  it("never throws on malformed input — invalid values become validation errors", () => {
    for (const bad of ["", "not a url", "github.com/x", "javascript:alert(1)"]) {
      expect(() => httpUrl.safeParse(bad)).not.toThrow();
      expect(httpUrl.safeParse(bad).success).toBe(false);
    }
  });

  it("accepts absolute http(s) URLs and the empty string used to clear a link", () => {
    expect(httpUrl.safeParse("http://localhost:3000/profile").success).toBe(true);
    expect(httpUrl.safeParse("https://example.com/x?y=1").success).toBe(true);
    expect(httpUrl.or(z.literal("")).safeParse("").success).toBe(true);
  });
});

describe("upload type rules (§9)", () => {
  it("magic-detected MIME must match extension; SVG/executables absent from allowlists", () => {
    expect(mimeMatchesExt("application/pdf", "a.pdf")).toBe(true);
    expect(mimeMatchesExt("application/pdf", "a.png")).toBe(false);
    expect(mimeMatchesExt("image/png", "evil.svg")).toBe(false);
    for (const rules of Object.values(PURPOSE_RULES)) {
      expect(rules.exts).not.toContain(".svg");
      expect(rules.exts).not.toContain(".exe");
      expect(rules.mimes).not.toContain("image/svg+xml");
    }
    expect(PURPOSE_RULES.assignment!.exts).toEqual([".pdf", ".zip"]);
  });

  it("accepts every recognized photo format plus MP4, and sizes them as images/video", () => {
    const cases = [
      ["image/jpeg", "photo.jpg"], ["image/jpeg", "photo.jfif"],
      ["image/png", "shot.png"], ["image/apng", "anim.png"],
      ["image/webp", "pic.webp"], ["image/gif", "anim.gif"],
      ["image/avif", "photo.avif"], ["image/heic", "iphone.heic"],
      ["image/heif", "iphone.heif"], ["image/tiff", "scan.tiff"],
      ["image/bmp", "old.bmp"], ["image/x-icon", "favicon.ico"],
      ["image/jxl", "photo.jxl"], ["image/jp2", "photo.jp2"],
      ["image/vnd.adobe.photoshop", "edit.psd"],
      ["image/x-adobe-dng", "raw.dng"], ["image/x-canon-cr2", "raw.cr2"],
      ["video/mp4", "clip.mp4"],
    ] as const;
    for (const [mime, name] of cases) {
      expect(mimeMatchesExt(mime, name)).toBe(true);
      expect(kindOfMime(mime)).not.toBeNull();
    }
    expect(kindOfMime("image/heic")).toBe("image");
    expect(kindOfMime("video/mp4")).toBe("video");
    for (const purpose of ["avatar", "cover", "content"]) {
      expect(PURPOSE_RULES[purpose]!.exts).toEqual(
        expect.arrayContaining([".gif", ".avif", ".heic", ".tiff", ".bmp"]),
      );
    }
    expect(PURPOSE_RULES.content!.exts).toContain(".mp4");
  });

  it("still rejects a mislabelled file (MIME does not belong to the extension)", () => {
    expect(mimeMatchesExt("image/png", "photo.jpg")).toBe(false);
    expect(mimeMatchesExt("video/mp4", "photo.png")).toBe(false);
  });

  it("detects photos and MP4s from a bounded header read of the temp file", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lt-upload-"));
    try {
      const jpg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9]);
      const mp4 = Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00, 0x69, 0x73, 0x6F, 0x6D, 0x69, 0x73, 0x6F, 0x32]);
      const jpgPath = path.join(dir, "photo.jpg");
      const mp4Path = path.join(dir, "clip.mp4");
      const fakePath = path.join(dir, "fake.jpg");
      fs.writeFileSync(jpgPath, jpg);
      fs.writeFileSync(mp4Path, mp4);
      fs.writeFileSync(fakePath, "not an image");

      await expect(detectFileType(jpgPath, jpg.length)).resolves.toEqual({ ext: "jpg", mime: "image/jpeg" });
      await expect(detectFileType(mp4Path, mp4.length)).resolves.toEqual({ ext: "mp4", mime: "video/mp4" });
      // A renamed non-image must stay undetected so the route rejects it.
      expect(await detectFileType(fakePath, 12)).toBeUndefined();
      // Empty / single-byte temp files (e.g. an aborted upload) are not images.
      expect(await detectFileType(jpgPath, 1)).toBeUndefined();
      expect(await detectFileType(jpgPath, 0)).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  // Regression guard for a production-only failure: file-type's file reader is
  // loaded via a non-literal dynamic import('strtok3') that serverless bundlers
  // cannot trace, so fileTypeFromFile throws ERR_MODULE_NOT_FOUND when deployed
  // even though it works locally. Detection must go through fileTypeFromBuffer.
  it("never imports fileTypeFromFile", () => {
    const source = fs.readFileSync(new URL("../src/modules/uploads.routes.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/import\s*\{[^}]*fileTypeFromFile/);
  });
});
