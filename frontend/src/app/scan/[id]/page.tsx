import { Suspense } from "react";
import { ScanClientView } from "./scan-client-view";

async function ScanPageContent({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scanId = parseInt(id, 10);
  return <ScanClientView scanId={scanId} />;
}

export default function ScanPage(props: {
  params: Promise<{ id: string }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-screen items-center justify-center bg-[#f7f9fc] text-[#748294] font-mono text-xs">
          Loading workspace...
        </div>
      }
    >
      <ScanPageContent {...props} />
    </Suspense>
  );
}
