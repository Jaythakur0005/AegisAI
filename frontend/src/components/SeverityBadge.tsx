interface SeverityBadgeProps {
  severity: string | null;
}

export default function SeverityBadge({
  severity,
}: SeverityBadgeProps) {
  const normalized = severity?.toLowerCase() ?? "unknown";

  return (
    <span className={`severity-badge severity-${normalized}`}>
      {severity ?? "Unknown"}
    </span>
  );
}
