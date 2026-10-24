import type { ReactNode } from "react";

export function Panel(props: { title: string; right?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <section className={`panel ${props.className ?? ""}`}>
      <header className="panel-head">
        <h2>{props.title}</h2>
        <div className="panel-right">{props.right}</div>
      </header>
      <div className="panel-body">{props.children}</div>
    </section>
  );
}

export function SevBadge({ severity }: { severity: string }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}
