import { Button } from '../brand';

export function LoadMore({ hasMore, loading, onClick }: { hasMore: boolean; loading: boolean; onClick(): void }) {
  if (!hasMore) return null;
  return (
    <div className="load-more">
      <Button variant="secondary" size="sm" onClick={onClick} disabled={loading}>
        {loading ? 'Loading' : 'Load more'}
      </Button>
    </div>
  );
}
