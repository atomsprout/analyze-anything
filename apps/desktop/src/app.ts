// What every screen shares: the backend, the language and colours, and ways to tell the user
// something or ask them to confirm.

import { clear, el } from "./dom";
import { word, type Word } from "./i18n";
import type { AppInfo, Backend, Lang, Theme } from "./types";

export interface App {
  backend: Backend;
  info: AppInfo;
  lang: Lang;
  theme: Theme;
  /** A word of the app's screens in the current language. */
  t(key: Word, values?: Record<string, string | number>): string;
  /** A short message at the bottom of the window; `error` ones stay until dismissed. */
  toast(message: string, error?: boolean): void;
  /** Asks the user to confirm something that cannot be undone. */
  confirm(message: string, action: string): Promise<boolean>;
}

/** `dark` or `light`: what `theme` means right now. */
export function resolvedTheme(theme: Theme): "dark" | "light" {
  if (theme !== "system") return theme;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

/** Reads a remembered choice; private browsing and the like may refuse storage. */
export function remembered<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = window.localStorage.getItem(key);
    return allowed.includes(value as T) ? (value as T) : fallback;
  } catch {
    return fallback;
  }
}

export function remember(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // The choice then lasts until the window closes.
  }
}

export function toaster(host: HTMLElement): (message: string, error?: boolean) => void {
  let timer = 0;
  return (message, error = false) => {
    window.clearTimeout(timer);
    clear(host);
    const close = () => clear(host);
    host.appendChild(
      el("div", { class: error ? "toast error" : "toast", role: error ? "alert" : "status" }, el("span", null, message), el("button", { type: "button", class: "plain", "aria-label": "×", onclick: close }, "×")),
    );
    if (!error) timer = window.setTimeout(close, 6000);
  };
}

export function confirmer(host: HTMLElement, lang: () => Lang): (message: string, action: string) => Promise<boolean> {
  return (message, action) =>
    new Promise((resolve) => {
      const finish = (answer: boolean) => {
        document.removeEventListener("keydown", onKey, true);
        clear(host);
        resolve(answer);
      };
      const onKey = (event: KeyboardEvent) => {
        if (event.key === "Escape") finish(false);
      };
      document.addEventListener("keydown", onKey, true);
      const cancel = el("button", { type: "button", class: "btn", onclick: () => finish(false) }, word(lang(), "cancel"));
      const dialog = el(
        "div",
        { class: "dialog", role: "alertdialog", "aria-modal": "true" },
        el("p", null, message),
        el("div", { class: "dialog-actions" }, cancel, el("button", { type: "button", class: "btn danger", onclick: () => finish(true) }, action)),
      );
      host.appendChild(el("div", { class: "backdrop", onclick: (event) => event.target === event.currentTarget && finish(false) }, dialog));
      cancel.focus();
    });
}
