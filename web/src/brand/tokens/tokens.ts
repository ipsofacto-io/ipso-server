// ipso design tokens. Generated from tokens.json, edit tokens.json, not this file.
// At runtime prefer the CSS variables (tokens.css): they follow data-theme.

export const tokens = {
  "color": {
    "light": {
      "surface": "#FBF2F3",
      "surface-raised": "#FFFCFD",
      "surface-sunken": "#F2E7E9",
      "line": "#E4D8DA",
      "line-strong": "#8C8485",
      "ink": "#1D181A",
      "ink-muted": "#696164",
      "rosa": "#F998BF",
      "on-rosa": "#1D181A",
      "rosa-soft": "#FFEBF3",
      "fucsia": "#C03476",
      "on-fucsia": "#FFFFFF",
      "menta": "#8BE7C0",
      "on-menta": "#1D181A",
      "menta-soft": "#DCF8EA",
      "menta-strong": "#0B764D",
      "carminio": "#A52B1E",
      "carminio-soft": "#FFE3DE",
      "on-carminio": "#FFFFFF",
      "action": "#1D181A",
      "action-hover": "#332B2F",
      "on-action": "#F998BF",
      "pietra": "#696164",
      "on-pietra": "#FBF2F3",
      "cursor": "#C03476",
      "link": "#C03476",
      "focus": "#C03476"
    },
    "dark": {
      "surface": "#171214",
      "surface-raised": "#231E20",
      "surface-sunken": "#100C0E",
      "line": "#373133",
      "line-strong": "#797275",
      "ink": "#FBF2F3",
      "ink-muted": "#B1A8AC",
      "rosa": "#F998BF",
      "on-rosa": "#1D181A",
      "rosa-soft": "#3D222C",
      "fucsia": "#F998BF",
      "on-fucsia": "#171214",
      "menta": "#8BE7C0",
      "on-menta": "#1D181A",
      "menta-soft": "#123226",
      "menta-strong": "#8BE7C0",
      "carminio": "#EE8676",
      "carminio-soft": "#3E1F1A",
      "on-carminio": "#171214",
      "action": "#F998BF",
      "action-hover": "#EC85AF",
      "on-action": "#1D181A",
      "pietra": "#8C8387",
      "on-pietra": "#171214",
      "cursor": "#F998BF",
      "link": "#F998BF",
      "focus": "#F998BF"
    }
  },
  "space": {
    "space-1": "4px",
    "space-2": "8px",
    "space-3": "12px",
    "space-4": "16px",
    "space-5": "24px",
    "space-6": "32px",
    "space-7": "48px",
    "space-8": "64px",
    "space-9": "96px"
  },
  "radius": {
    "radius-sm": "6px",
    "radius-md": "12px",
    "radius-lg": "20px",
    "radius-pill": "999px"
  },
  "fonts": {
    "mono": "\"JetBrains Mono\", ui-monospace, \"SF Mono\", Menlo, monospace",
    "sans": "\"Instrument Sans\", ui-sans-serif, system-ui, sans-serif"
  },
  "type": {
    "display-xl": {
      "fontSize": "56px",
      "lineHeight": "60px",
      "fontWeight": 700,
      "letterSpacing": "-0.03em",
      "fontFamily": "mono"
    },
    "display": {
      "fontSize": "40px",
      "lineHeight": "46px",
      "fontWeight": 700,
      "letterSpacing": "-0.025em",
      "fontFamily": "mono"
    },
    "heading": {
      "fontSize": "24px",
      "lineHeight": "32px",
      "fontWeight": 600,
      "letterSpacing": "-0.01em",
      "fontFamily": "mono"
    },
    "title": {
      "fontSize": "20px",
      "lineHeight": "28px",
      "fontWeight": 600,
      "fontFamily": "sans"
    },
    "body-lg": {
      "fontSize": "18px",
      "lineHeight": "28px",
      "fontWeight": 400,
      "fontFamily": "sans"
    },
    "body": {
      "fontSize": "16px",
      "lineHeight": "24px",
      "fontWeight": 400,
      "fontFamily": "sans"
    },
    "small": {
      "fontSize": "14px",
      "lineHeight": "20px",
      "fontWeight": 400,
      "fontFamily": "sans"
    },
    "label": {
      "fontSize": "11px",
      "lineHeight": "16px",
      "fontWeight": 600,
      "letterSpacing": "0.06em",
      "fontFamily": "mono"
    },
    "code": {
      "fontSize": "14px",
      "lineHeight": "22px",
      "fontWeight": 400,
      "fontFamily": "mono"
    },
    "data": {
      "fontSize": "13px",
      "lineHeight": "20px",
      "fontWeight": 400,
      "fontFamily": "mono"
    }
  }
} as const;

export type Theme = keyof typeof tokens.color;
export type ColorToken = keyof typeof tokens.color.light;

/** `var(--name)` for a colour, space or radius token, e.g. cssVar('rosa'). */
export const cssVar = (name: ColorToken | keyof typeof tokens.space | keyof typeof tokens.radius) => `var(--${name})`;
