/**
 * AI transparency label required by ADR-0152 and ADR-0158 whenever an AI-generated artifact or
 * engine: llm verdict is rendered in the user interface.
 */
export function ModelLabel({ modelID, promptVersion }: { modelID: string; promptVersion?: string }) {
  const detail = promptVersion ? `${modelID}, prompt ${promptVersion}` : modelID;
  return (
    <div>
      <dt>AI-generated</dt>
      <dd className="mono">{detail}</dd>
    </div>
  );
}
