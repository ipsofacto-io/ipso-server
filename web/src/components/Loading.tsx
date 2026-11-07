export function Loading({ what }: { what: string }) {
  return (
    <p className="loading" role="status">
      Loading {what}
    </p>
  );
}
