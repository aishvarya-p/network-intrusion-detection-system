/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0B0F19",          // Deep dark space background
          surface: "#111827",     // Card and panel surface
          surface2: "#162032",    // Secondary elevated surface
          border: "#1F2937",      // Subtle card border
          borderLight: "#374151", // Emphasized border
          text: "#F3F4F6",        // Primary text
          muted: "#9CA3AF",       // Secondary/muted text
          cyan: "#06B6D4",        // Primary accent
          blue: "#3B82F6",        // Primary brand
          emerald: "#10B981",     // Normal / Safe status
          amber: "#F59E0B",       // Warning / Medium status
          rose: "#F43F5E",        // Critical / High threat
          purple: "#8B5CF6",      // Rule/hybrid detection
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
}
