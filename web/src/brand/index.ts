// ipso: components and tokens for React 18+.
// Import the styles once, at the root of the app:
//   import './styles/fonts.css';   // Google Fonts: JetBrains Mono + Instrument Sans
//   import './styles/tokens.css';  // CSS variables, light and dark (data-theme)
//   import './styles/ipso.css';    // component styles

export { Wordmark, type WordmarkProps, type WordmarkTone } from './components/Wordmark';
export { Mascot, type MascotProps, type MascotState, type MascotTone } from './components/Mascot';
export { Button, type ButtonProps, type ButtonVariant } from './components/Button';
export { Status, type StatusProps, type StatusTone } from './components/Status';
export { TextField, type TextFieldProps } from './components/TextField';
export { Code, type CodeProps } from './components/Code';
export { DecisionReceipt, type DecisionReceiptProps } from './components/DecisionReceipt';
export { IntegrationBadge, type IntegrationBadgeProps } from './components/IntegrationBadge';
export * as geometry from './components/brand-geometry';
export { tokens, cssVar, type ColorToken, type Theme } from './tokens/tokens';
