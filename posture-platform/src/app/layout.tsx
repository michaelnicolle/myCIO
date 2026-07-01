import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'myCIO Security Posture Platform',
  description: 'Microsoft 365 security posture, ITDR & ISPM for managed customer tenants.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
