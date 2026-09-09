import { describe, expect, it } from "vitest";
import {
  buildCredentialSafetyPrompt,
  SECRET_EGRESS_USAGE_PROMPT,
} from "./transcript-credential-safety.js";

describe("credential transcript policy", () => {
  it.each([undefined, true, false])(
    "preserves protected tools with transcript policy %s",
    (allow) => {
      for (const name of [undefined, "secrets", "openclaw.secrets"]) {
        const prompt = buildCredentialSafetyPrompt(name, { allowCredentialsInTranscript: allow });
        expect(prompt.includes("Use host-owned masked credential entry")).toBe(allow === false);
        expect(prompt).toContain("Never ask users to paste passwords or reusable credentials");
        expect(prompt).toContain("user-provided short-lived one-time codes or OAuth callbacks");
        expect(prompt).toContain("preserving state, PKCE, expiry, and account checks");
        if (name) {
          expect(prompt).toContain(`\`${name}\`: list metadata first`);
          expect(prompt).toContain(
            "Human masked entry -> protected shared store; metadata/ref only",
          );
          expect(prompt).toContain(
            "Gateway egress needs enabled proxy + allowed hosts; no plaintext fallback",
          );
          expect(prompt).toContain(SECRET_EGRESS_USAGE_PROMPT);
        } else {
          expect(prompt).not.toContain("`secrets`");
          expect(prompt).not.toContain("SecretRef");
        }
      }
    },
  );
});
