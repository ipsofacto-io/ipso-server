import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

interface AppValue {
  /** null until a call has answered: the app cannot know before it asks. */
  signedIn: boolean | null;
  setSignedIn(value: boolean): void;
  /** True while any request is in flight. The wordmark's cursor blinks only then (the kit's rule). */
  busy: boolean;
  /** Counts a request as in flight and returns the call that ends it. */
  begin(): () => void;
}

const idle: AppValue = { signedIn: null, setSignedIn: () => {}, busy: false, begin: () => () => {} };

const AppContext = createContext<AppValue>(idle);

export function AppProvider({ children }: { children: ReactNode }) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
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
  const value = useMemo<AppValue>(() => ({ signedIn, setSignedIn, busy: inFlight > 0, begin }), [signedIn, inFlight, begin]);
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppValue {
  return useContext(AppContext);
}
