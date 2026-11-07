import './fonts';
import './brand/styles/tokens.css';
import './brand/styles/ipso.css';
import './brand/styles/base.css';
import './styles/app.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import { followSystemTheme } from './theme';

followSystemTheme(document.documentElement, window.matchMedia('(prefers-color-scheme: dark)'));

const root = document.getElementById('root');
if (root === null) throw new Error('index.html has no #root');
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
