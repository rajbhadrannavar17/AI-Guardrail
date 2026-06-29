export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        terminal: "#0d1117",
        accent: "#00ff88",
        panel: "#111827",
        line: "#263241",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "SFMono-Regular", "Consolas", "monospace"],
      },
      animation: {
        pulseLine: "pulseLine 1.8s ease-in-out infinite",
        typeIn: "typeIn 1.1s steps(40, end)",
      },
      keyframes: {
        pulseLine: {
          "0%, 100%": { opacity: "0.45" },
          "50%": { opacity: "1" },
        },
        typeIn: {
          from: { width: "0" },
          to: { width: "100%" },
        },
      },
    },
  },
  plugins: [],
}
