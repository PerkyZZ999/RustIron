import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { AppRouter } from "./router";
import "./globals.css";

const root = document.querySelector("#root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <AppRouter />
  </StrictMode>,
);
