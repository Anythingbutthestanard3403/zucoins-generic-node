import type { ReactNode } from "react";
import qrcode from "qrcode-generator";

// client-side QR rendering of the otpauth:// enrolment URI.
// No server change: this renders exactly the string the server already
// returns. Bundled qrcode-generator — no network egress.

const QR_QUIET_ZONE_MODULES = 4;
const QR_PIXELS = 200;

/** Renders `value` as an inline SVG QR code. Secret text stays the fallback. */
export function TotpQrCode({ value }: { value: string }) {
  // qrcode-generator throws when `value` exceeds QR capacity
  // (~2.3 KB at type 0 / EC "M"). The input space is bounded in practice
  // (fixed username, only issuer varies), but a hostile operator-config
  // issuer could push past the limit. Catch here and render nothing; the
  // page already shows the text secret as a manual-entry fallback.
  let qr: ReturnType<typeof qrcode>;
  try {
    qr = qrcode(0, "M");
    qr.addData(value, "Byte");
    qr.make();
  } catch {
    return null;
  }
  const moduleCount = qr.getModuleCount();
  const size = moduleCount + QR_QUIET_ZONE_MODULES * 2;

  const rects: ReactNode[] = [];
  for (let row = 0; row < moduleCount; row++) {
    for (let col = 0; col < moduleCount; col++) {
      if (qr.isDark(row, col)) {
        rects.push(
          <rect
            key={`${row}-${col}`}
            x={col + QR_QUIET_ZONE_MODULES}
            y={row + QR_QUIET_ZONE_MODULES}
            width={1}
            height={1}
          />,
        );
      }
    }
  }

  return (
    <svg
      role="img"
      aria-label="QR code for the authenticator secret"
      data-testid="totp-qr-code"
      width={QR_PIXELS}
      height={QR_PIXELS}
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
    >
      <g fill="#000">{rects}</g>
    </svg>
  );
}
