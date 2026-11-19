// Building the page. Text reaches it only as text nodes and attribute values: nothing here, or
// anywhere in the app, parses a string as markup.

type Child = Node | string | null | undefined | false | Child[];

export interface Props {
  class?: string;
  title?: string;
  type?: string;
  id?: string;
  role?: string;
  hidden?: boolean;
  disabled?: boolean;
  checked?: boolean;
  placeholder?: string;
  value?: string;
  tabindex?: string;
  lang?: string;
  for?: string;
  [aria: `aria-${string}`]: string;
  [data: `data-${string}`]: string;
  onclick?: (event: MouseEvent) => void;
  oninput?: (event: Event) => void;
  onchange?: (event: Event) => void;
  onkeydown?: (event: KeyboardEvent) => void;
  onsubmit?: (event: SubmitEvent) => void;
  onscroll?: (event: Event) => void;
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value == null || value === false) continue;
    if (typeof value === "function") node.addEventListener(key.slice(2), value as EventListener);
    else if (key === "class") node.className = String(value);
    else if (key === "hidden" || key === "disabled" || key === "checked") (node as unknown as Record<string, boolean>)[key] = true;
    else if (key === "value") (node as unknown as HTMLInputElement).value = String(value);
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child == null || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else parent.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
}

export function clear<T extends Node>(node: T): T {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}
