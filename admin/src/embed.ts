import { useEffect, useRef, type RefObject } from "react";

export const isEmbedded: boolean = (() => {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
})();

export type EmbedMessage =
  | { source: "ma_hono"; type: "login:ready"; height: number }
  | { source: "ma_hono"; type: "login:resize"; height: number };

export function postEmbedMessage(message: EmbedMessage): void {
  if (!isEmbedded) return;
  window.parent.postMessage(message, "*");
}

export function useEmbedReporter(
  ref: RefObject<HTMLElement | null>,
  ready: boolean
): void {
  const readySent = useRef(false);

  useEffect(() => {
    if (!isEmbedded) return;
    const element = ref.current;
    if (!element) return;

    const observer = new ResizeObserver(() => {
      postEmbedMessage({
        source: "ma_hono",
        type: "login:resize",
        height: Math.ceil(element.getBoundingClientRect().height)
      });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);

  useEffect(() => {
    if (!isEmbedded || !ready || readySent.current) return;
    readySent.current = true;
    postEmbedMessage({
      source: "ma_hono",
      type: "login:ready",
      height: ref.current ? Math.ceil(ref.current.getBoundingClientRect().height) : 0
    });
  }, [ready, ref]);
}
