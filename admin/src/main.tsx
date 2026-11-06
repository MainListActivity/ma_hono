import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";
import { isEmbedded } from "./embed";

if (isEmbedded) {
  document.documentElement.dataset.embedded = "true";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
