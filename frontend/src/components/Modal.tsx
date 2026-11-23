import { ReactNode } from "react";
import { X } from "lucide-react";

export default function Modal({ open, title, onClose, children }: { open: boolean; title: string; onClose: () => void; children: ReactNode }) {
  if (!open) return null;
  return (
    <div className="modal-mask" onClick={onClose}>
      <section className="modal" onClick={(event) => event.stopPropagation()}>
        <header>
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="关闭"><X size={18} /></button>
        </header>
        <div style={{ paddingTop: 14 }}>{children}</div>
      </section>
    </div>
  );
}
