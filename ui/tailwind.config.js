/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: '#020617', // Slate 950
        surface: {
          1: '#090d16',
          2: '#0f172a',    // Slate 900
          3: '#1e293b',    // Slate 800
          inset: '#030712' // Zinc 950 code bed
        },
        border: {
          subtle: '#1e293b',
          interactive: '#334155',
          focus: '#475569'
        },
        emerald: {
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          900: '#064e3b'
        },
        rose: {
          400: '#fb7185',
          500: '#f43f5e',
          900: '#4c0519'
        },
        sky: {
          400: '#38bdf8',
          500: '#0ea5e9',
          900: '#082f49'
        },
        amber: {
          400: '#fbbf24',
          500: '#f59e0b',
          900: '#451a03'
        }
      },
      fontFamily: {
        sans: ['Geist', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
