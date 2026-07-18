import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { useApp } from "./stores/app";
import "./styles/globals.css";

// Subscribe to bridge events BEFORE any component mounts — child route effects would
// otherwise fire actions (e.g. auto-connect) before a parent effect could subscribe.
useApp.getState().init();

// Apply the frozen flag (screenshots) to the root before first paint.
const params = new URLSearchParams(location.search);
if (params.get("freeze") === "1") document.documentElement.setAttribute("data-freeze", "1");
const theme = params.get("theme");
if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
