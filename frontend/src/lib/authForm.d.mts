export type RegistrationFields = {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
};
export function validateRegistration(fields: RegistrationFields): "name" | "email" | "password" | "confirmation" | null;
export function authErrorMessage(action: "register" | "login", status?: number, serverMessage?: string): string;
export function createAccountAndContinue(name: string, email: string, password: string, register: (name: string, email: string, password: string) => Promise<{ id: string; email: string }>, navigate: (path: string, options: { replace: boolean; state?: unknown }) => void): Promise<{ id: string; email: string }>;
export function establishSession(email: string, password: string, login: (email: string, password: string) => Promise<{ access_token?: string | null; user?: { id: string } | null }>, storage: Pick<Storage, "setItem">, navigate: (path: string, options: { replace: boolean }) => void): Promise<{ access_token?: string | null; user?: { id: string } | null }>;
export function publicRouteRedirect(isAuthenticated: boolean): "/dashboard" | null;
export function protectedRouteRedirect(isAuthenticated: boolean): "/login" | null;
