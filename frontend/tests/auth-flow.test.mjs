import assert from "node:assert/strict";
import test from "node:test";
import { authErrorMessage, createAccountAndContinue, establishSession, protectedRouteRedirect, publicRouteRedirect, validateRegistration } from "../src/lib/authForm.mjs";
import { resolveApiBaseUrl } from "../src/lib/apiBase.mjs";
import { readFile } from "node:fs/promises";

test("registration validates required fields and the backend password bounds", () => {
  assert.equal(validateRegistration({ name: " A ", email: "person@example.com", password: "password1", confirmPassword: "password1" }), "name");
  assert.equal(validateRegistration({ name: "Ada", email: "bad-email", password: "password1", confirmPassword: "password1" }), "email");
  assert.equal(validateRegistration({ name: "Ada", email: "ada@example.com", password: "short", confirmPassword: "short" }), "password");
  assert.equal(validateRegistration({ name: "Ada", email: "ada@example.com", password: "x".repeat(129), confirmPassword: "x".repeat(129) }), "password");
  assert.equal(validateRegistration({ name: "Ada", email: "ada@example.com", password: "password1", confirmPassword: "password2" }), "confirmation");
  assert.equal(validateRegistration({ name: "Ada Lovelace", email: "ada@example.com", password: "password1", confirmPassword: "password1" }), null);
});

test("successful registration follows the user response with a sign-in redirect", async () => {
  const calls = [];
  const user = { id: "user-1", name: "Ada", email: "ada@example.com", is_active: true };
  const result = await createAccountAndContinue("Ada", "ada@example.com", "password1", async (...args) => {
    calls.push(["register", ...args]);
    return user;
  }, (...args) => calls.push(["navigate", ...args]));
  assert.equal(result, user);
  assert.deepEqual(calls, [
    ["register", "Ada", "ada@example.com", "password1"],
    ["navigate", "/login", { replace: true, state: { accountCreated: true } }],
  ]);
});

test("duplicate, invalid, unavailable, and network registration errors are actionable", () => {
  assert.match(authErrorMessage("register", 409), /already exists/i);
  assert.match(authErrorMessage("register", 422), /check your/i);
  assert.match(authErrorMessage("register", 503), /temporarily unavailable/i);
  assert.equal(authErrorMessage("register", undefined, "Unable to reach server"), "Unable to reach server");
});

test("successful login stores a real token and user before navigating", async () => {
  const calls = [];
  const storage = { setItem: (...args) => calls.push(["store", ...args]) };
  const result = await establishSession("ada@example.com", "password1", async (...args) => {
    calls.push(["login", ...args]);
    return { access_token: "token-value", user: { id: "user-1", email: "ada@example.com" } };
  }, storage, (...args) => calls.push(["navigate", ...args]));
  assert.equal(result.access_token, "token-value");
  assert.deepEqual(calls, [
    ["login", "ada@example.com", "password1"],
    ["store", "scamshield_access_token", "token-value"],
    ["store", "scamshield_user", JSON.stringify({ id: "user-1", email: "ada@example.com" })],
    ["navigate", "/dashboard", { replace: true }],
  ]);
});

test("failed or incomplete login never stores a token or redirects", async () => {
  const calls = [];
  const storage = { setItem: (...args) => calls.push(["store", ...args]) };
  await assert.rejects(establishSession("ada@example.com", "wrong", async () => { throw new Error("invalid"); }, storage, (...args) => calls.push(args)), /invalid/);
  await assert.rejects(establishSession("ada@example.com", "password1", async () => ({ user: { id: "user-1" } }), storage, (...args) => calls.push(args)), /valid session/);
  assert.deepEqual(calls, []);
});

test("login errors distinguish credentials, throttling, outage, and network failures", () => {
  assert.equal(authErrorMessage("login", 401), "Invalid email or password.");
  assert.match(authErrorMessage("login", 429), /too many/i);
  assert.match(authErrorMessage("login", 503), /temporarily unavailable/i);
  assert.equal(authErrorMessage("login", undefined, "Unable to reach server"), "Unable to reach server");
});

test("API base URL uses configured production URL and localhost only in development", () => {
  assert.equal(resolveApiBaseUrl("https://api.example.com/api/v1///", false), "https://api.example.com/api/v1");
  assert.equal(resolveApiBaseUrl(undefined, true), "http://127.0.0.1:8000/api/v1");
  assert.equal(resolveApiBaseUrl(undefined, false), "");
});

test("public and protected routes redirect according to the saved session", () => {
  assert.equal(publicRouteRedirect(false), null);
  assert.equal(publicRouteRedirect(true), "/dashboard");
  assert.equal(protectedRouteRedirect(false), "/login");
  assert.equal(protectedRouteRedirect(true), null);
});

test("Netlify serves the SPA for direct route visits and refreshes", async () => {
  const fallback = await readFile(new URL("../public/_redirects", import.meta.url), "utf8");
  assert.match(fallback.trim(), /^\/\* \/index\.html 200$/);
});
