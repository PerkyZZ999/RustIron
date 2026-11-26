// W629 (P29 Slice 9): Client-side Better Auth session context for the Console UI.
import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";

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
  try {
    const res = await fetch("/api/accounts/status", {
      cache: "no-store",
      credentials: "same-origin",
    });
    if (res.ok) {
      const body = (await res.json()) as ConsoleAuthStatus;
      if (body && body.auth_provider === "better-auth") return body;
    }
  } catch {
    // Offline / unit-test mode without auth endpoint keeps status null.
  }
  return null;
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
    try {
      await fetch("/api/auth/sign-out", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
    } finally {
      const next = await fetchAuthStatus();
      if (next) setStatus(next);
      setResolved(true);
    }
  }, []);

  return (
    <AuthContext.Provider value={{ status, loading, resolved, refresh, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
