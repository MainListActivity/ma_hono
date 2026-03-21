import type { ReactNode } from "react";
export default function Modal({ children }: { title: string; onClose: () => void; children: ReactNode }) {
  return <div>{children}</div>;
}
