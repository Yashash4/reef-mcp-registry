import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-inter)", "Inter", "system-ui", "sans-serif"],
        display: ["var(--font-instrument-serif)", "Instrument Serif", "Georgia", "serif"],
        mono: ["var(--font-jetbrains-mono)", "JetBrains Mono", "monospace"],
      },
      colors: {
        // Match reef-overview.html palette verbatim — zinc-950 background +
        // semantic colors. The five named hues are how the rest of Reef
        // tags its semantics: emerald = safe, cyan = MCP, red = attack,
        // amber = RIA / pending, violet = Gemini.
        bg: "#0a0a0a",
        surface: "#111113",
        "surface-2": "#18181b",
        border: "#27272a",
        "border-soft": "#1f1f23",
        text: "#fafafa",
        "text-2": "#a1a1aa",
        "text-3": "#71717a",
        emerald: "#10b981",
        "emerald-soft": "rgba(16,185,129,0.12)",
        cyan: "#06b6d4",
        "cyan-soft": "rgba(6,182,212,0.12)",
        red: "#ef4444",
        "red-soft": "rgba(239,68,68,0.12)",
        amber: "#f59e0b",
        "amber-soft": "rgba(245,158,11,0.12)",
        violet: "#a78bfa",
        "violet-soft": "rgba(167,139,250,0.12)",
      },
      letterSpacing: {
        tightest: "-0.03em",
        tighter: "-0.02em",
      },
      animation: {
        "pulse-soft": "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        ripple: "ripple 1.2s ease-out forwards",
        "shark-circle": "shark-circle 14s linear infinite",
      },
      keyframes: {
        ripple: {
          "0%": { transform: "scale(0.4)", opacity: "0.9" },
          "100%": { transform: "scale(2.4)", opacity: "0" },
        },
        "shark-circle": {
          "0%": { transform: "rotate(0deg) translateX(58px) rotate(0deg)" },
          "100%": { transform: "rotate(360deg) translateX(58px) rotate(-360deg)" },
        },
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
export default config;
