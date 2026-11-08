import { useEffect, useRef } from 'react';

/** A ref for a block that takes the focus when it appears, such as the answer to a form that just replaced it. */
export function useFocusOnMount<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return ref;
}
