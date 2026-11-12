import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

interface AppValue {
  /** null until a call has answered: the app cannot know before it asks. */
  signedIn: boolean | null;
  setSignedIn(value: boolean): void;
  /** True while any request is in flight. The wordmark's cursor blinks only then (the kit's rule). */
  busy: boolean;
  /** Counts a request as in flight and returns the call that ends it. */
  begin(): () => void;
  /**
   * Whether the Export entry is shown: false once a read of the export was refused (401 or 403), true after any
   * other answer, null until one was made. No route says what role a person holds (ADR-0110, ADR-0115).
   */
  canExport: boolean | null;
  setCanExport(value: boolean | null): void;
}

const idle: AppValue = { signedIn: null, setSignedIn: () => {}, busy: false, begin: () => () => {}, canExport: null, setCanExport: () => {} };

const AppContext = createContext<AppValue>(idle);

export function AppProvider({ children }: { children: ReactNode }) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [canExport, setCanExport] = useState<boolean | null>(null);
  const [inFlight, setInFlight] = useState(0);
  const begin = useCallback(() => {
    let ended = false;
    setInFlight((n) => n + 1);
    return () => {
      if (!ended) {
        ended = true;
        setInFlight((n) => n - 1);
      }
    };
  }, []);
  const value = useMemo<AppValue>(() => ({ signedIn, setSignedIn, busy: inFlight > 0, begin, canExport, setCanExport }), [signedIn, inFlight, begin, canExport]);
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppValue {
  return useContext(AppContext);
}
