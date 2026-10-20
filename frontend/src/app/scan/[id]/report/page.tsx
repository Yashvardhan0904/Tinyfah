import { Suspense } from "react";
import { ReportClientView } from "./report-client-view";

async function ReportPageContent({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scanId = parseInt(id, 10);
  return <ReportClientView scanId={scanId} />;
}

export default function ReportPage(props: {
  params: Promise<{ id: string }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-screen items-center justify-center bg-[#f7f9fc] text-[#748294] font-mono text-xs">
          Loading security report...
        </div>
      }
    >
      <ReportPageContent {...props} />
    </Suspense>
  );
}
