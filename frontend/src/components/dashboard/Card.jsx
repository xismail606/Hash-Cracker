// Translucent card shell header shared by every dashboard section.

export function CardHeader({ icon, title, right, id }) {
  return (
    <div className="card-header flex items-center justify-between px-5 py-3">
      <h2 id={id} className="flex items-center gap-2.5 text-sm font-bold text-text">
        <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-accent/20 bg-accent/10 text-accent">
          {icon}
        </span>
        {title}
      </h2>
      {right}
    </div>
  );
}

export default CardHeader;
