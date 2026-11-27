import { defineConfig } from "oxlint";

export default defineConfig({
  plugins: ["react", "typescript", "oxc", "jsx-a11y"],
  categories: {
    correctness: "error",
    suspicious: "warn",
  },
  rules: {
    "react/rules-of-hooks": "error",
    "react/jsx-key": "error",
    // Automatic JSX runtime (tsconfig jsx: react-jsx).
    "react/react-in-jsx-scope": "off",
    // Suggested replacements are the wrong elements: role=group on a
    // button cluster is not a fieldset, role=status is not output, and
    // the chart/evidence marks are composite graphics, not content images.
    "jsx-a11y/prefer-tag-over-role": "off",
    // W679 (typescript-expert): keep the type system's escape hatches at zero.
    "typescript/no-explicit-any": "error",
    "typescript/ban-ts-comment": "error",
    "typescript/no-non-null-assertion": "error",
  },
  ignorePatterns: ["dist/**"],
});
