"use client";

export default function HexView({ bytes }: { bytes: Uint8Array }) {
  const rows: React.ReactNode[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    rows.push(
      <div key={off} className="whitespace-pre">
        <span className="text-[var(--color-dim)]">
          {off.toString(16).padStart(8, "0")}
        </span>
        {"  "}
        {hex.padEnd(47, " ")}
        {"  "}
        {ascii}
      </div>,
    );
  }
  return <div className="text-[11px] leading-4">{rows}</div>;
}
