import '@testing-library/jest-dom/vitest';

import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

import { forgetScopes } from '../views/Scopes';

afterEach(() => {
  cleanup();
  forgetScopes();
});
