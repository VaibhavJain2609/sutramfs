import type { Metadata } from "next";
import "./globals.css";
import { MountsProvider } from "@/lib/mounts";
import { ToastProvider } from "@/lib/toast";
import { ActivityProvider } from "@/lib/activity";
import Shell from "@/components/shell";

export const metadata: Metadata = {
  title: "sutramfs",
  description: "SUTRAM-FS forensic filesystem workbench",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <ToastProvider>
          <ActivityProvider>
            <MountsProvider>
              <Shell>{children}</Shell>
            </MountsProvider>
          </ActivityProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
