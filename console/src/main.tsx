import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { AppRouter } from "./router";
import { settleSkippedTransitions } from "./view-transitions";
import "./globals.css";

settleSkippedTransitions(document);

const root = document.querySelector("#root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <AppRouter />
  </StrictMode>,
);
