// Browser-local console preferences (Settings page, opaque-chrome transparency, and reduced motion).
// Stored only in localStorage; never touches host state or security policy.
import {
  createContext,
  type ReactNode,
  useCallback,
  use,
  useEffect,
  useMemo,
  useState,
} from "react";

export type TimeDisplay = "utc" | "local";
export type MetricsRange = "1h" | "6h" | "24h" | "7d";
export type TransparencyPref = "system" | "reduce";
export type MotionPref = "system" | "reduce";
export type RowsPerPage = 10 | 25 | 50 | 100;

export type ConsolePreferences = {
  timeDisplay: TimeDisplay;
  metricsRange: MetricsRange;
  transparency: TransparencyPref;
  motion: MotionPref;
  rowsPerPage: RowsPerPage;
};

const defaultPreferences: ConsolePreferences = {
  timeDisplay: "utc",
  metricsRange: "24h",
  transparency: "system",
  motion: "system",
  rowsPerPage: 25,
};

const STORAGE_KEY = "ri-prefs";
const VALID_RANGES = new Set<string>(["1h", "6h", "24h", "7d"]);
const VALID_ROWS = new Set<number>([10, 25, 50, 100]);

function pickRange(value: unknown): MetricsRange {
  return typeof value === "string" && VALID_RANGES.has(value) ? (value as MetricsRange) : "24h";
}

function pickRows(value: unknown): RowsPerPage {
  return typeof value === "number" && VALID_ROWS.has(value) ? (value as RowsPerPage) : 25;
}

function loadPreferences(): ConsolePreferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultPreferences;
    const parsed = JSON.parse(raw) as Partial<ConsolePreferences>;
    return {
      timeDisplay: parsed.timeDisplay === "local" ? "local" : "utc",
      metricsRange: pickRange(parsed.metricsRange),
      transparency: parsed.transparency === "reduce" ? "reduce" : "system",
      motion: parsed.motion === "reduce" ? "reduce" : "system",
      rowsPerPage: pickRows(parsed.rowsPerPage),
    };
  } catch {
    return defaultPreferences;
  }
}

const PrefsContext = createContext<{
  prefs: ConsolePreferences;
  savePrefs: (next: ConsolePreferences) => void;
}>({
  prefs: defaultPreferences,
  savePrefs: () => {},
});

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<ConsolePreferences>(loadPreferences);

  useEffect(() => {
    if (prefs.transparency === "reduce") {
      document.documentElement.dataset.transparency = "reduce";
    } else {
      delete document.documentElement.dataset.transparency;
    }
  }, [prefs.transparency]);

  useEffect(() => {
    if (prefs.motion === "reduce") {
      document.documentElement.dataset.motion = "reduce";
    } else {
      delete document.documentElement.dataset.motion;
    }
  }, [prefs.motion]);

  const savePrefs = useCallback((next: ConsolePreferences) => {
    setPrefs(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Storage may be unavailable; preference still applies for this visit.
    }
  }, []);
  const value = useMemo(() => ({ prefs, savePrefs }), [prefs, savePrefs]);

  return <PrefsContext.Provider value={value}>{children}</PrefsContext.Provider>;
}

export function usePreferences() {
  return use(PrefsContext);
}
