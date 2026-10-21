import { Suspense } from "react";
import { TechnicalReportClientView } from "./technical-report-client-view";

async function TechnicalReportPageContent({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scanId = parseInt(id, 10);
  return <TechnicalReportClientView scanId={scanId} />;
}

export default function TechnicalReportPage(props: {
  params: Promise<{ id: string }>;
}) {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-screen items-center justify-center bg-[#f7f9fc] text-[#748294] font-mono text-xs">
          Loading detailed technical report...
        </div>
      }
    >
      <TechnicalReportPageContent {...props} />
    </Suspense>
  );
}
