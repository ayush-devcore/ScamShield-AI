export function validateRegistration({ name, email, password, confirmPassword }) {
  if (name.trim().length < 2) return "name";
  if (!/^.+@[^.\s]+(?:\.[^.\s]+)+$/.test(email.trim())) return "email";
  if (password.length < 8 || password.length > 128) return "password";
  if (password !== confirmPassword) return "confirmation";
  return null;
}

export function authErrorMessage(action, status, serverMessage = "") {
  if (action === "register") {
    if (status === 409) return "An account with this email already exists. Sign in or use another email address.";
    if (status === 422) return "Please check your name, email address, and password, then try again.";
    if (status === 503) return "Registration is temporarily unavailable. Please try again shortly.";
    return serverMessage || "We could not create your account. Please try again.";
  }
  if (status === 401) return "Invalid email or password.";
  if (status === 429) return "Too many failed sign-in attempts. Please wait and try again.";
  if (status === 503) return "Sign in is temporarily unavailable. Please try again shortly.";
  return serverMessage || "Unable to sign in. Please try again.";
}

export async function createAccountAndContinue(name, email, password, register, navigate) {
  const user = await register(name, email, password);
  if (!user?.id || !user?.email) throw new Error("Registration did not return a valid account. Please try signing in.");
  navigate("/login", { replace: true, state: { accountCreated: true } });
  return user;
}

export async function establishSession(email, password, login, storage, navigate) {
  const result = await login(email, password);
  if (!result?.access_token || !result?.user?.id) throw new Error("Sign in did not return a valid session. Please try again.");
  storage.setItem("scamshield_access_token", result.access_token);
  storage.setItem("scamshield_user", JSON.stringify(result.user));
  navigate("/dashboard", { replace: true });
  return result;
}

export function publicRouteRedirect(isAuthenticated) {
  return isAuthenticated ? "/dashboard" : null;
}

export function protectedRouteRedirect(isAuthenticated) {
  return isAuthenticated ? null : "/login";
}
