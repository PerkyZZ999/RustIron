// W629 (P29 Slice 9): Client-side Better Auth session context for the Console UI.
import { consoleRequest } from "./console-request";
import {
  createContext,
  type ReactNode,
  useCallback,
  use,
  useEffect,
  useMemo,
  useState,
} from "react";

import type { ConsoleAuthStatus } from "./auth-backend";

type AuthContextValue = {
  status: ConsoleAuthStatus | null;
  loading: boolean;
  resolved: boolean;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue>({
  status: null,
  loading: false,
  resolved: true,
  refresh: async () => {},
  signOut: async () => {},
});

async function fetchAuthStatus(): Promise<ConsoleAuthStatus | null> {
  // Offline and unit-test modes without the auth endpoint keep the status null.
  const reply = await consoleRequest<ConsoleAuthStatus | null>("/api/accounts/status");
  return reply.ok && reply.data?.auth_provider === "better-auth" ? reply.data : null;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<ConsoleAuthStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [resolved, setResolved] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    const next = await fetchAuthStatus();
    if (next) setStatus(next);
    setResolved(true);
    setLoading(false);
  }, []);

  useEffect(() => {
    let active = true;
    void fetchAuthStatus()
      .then((next) => {
        if (active && next) setStatus(next);
      })
      .finally(() => {
        if (active) setResolved(true);
      });
    return () => {
      active = false;
    };
  }, []);

  const signOut = useCallback(async () => {
    await consoleRequest("/api/auth/sign-out", { method: "POST", json: {} });
    const next = await fetchAuthStatus();
    if (next) setStatus(next);
    setResolved(true);
  }, []);

  const value = useMemo(
    () => ({ status, loading, resolved, refresh, signOut }),
    [status, loading, resolved, refresh, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return use(AuthContext);
}
