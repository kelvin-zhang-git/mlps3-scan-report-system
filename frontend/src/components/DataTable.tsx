import { ReactNode, useEffect, useMemo, useState } from "react";

type Column<T> = { key: string; title: string; render: (row: T) => ReactNode };

export default function DataTable<T>({
  rows,
  columns,
  onRow,
  pageSize = 12,
  empty = "没有数据",
}: {
  rows: T[];
  columns: Column<T>[];
  onRow?: (row: T) => void;
  pageSize?: number;
  empty?: string;
}) {
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [rows.length, pageSize]);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, pages - 1);
  const slice = useMemo(() => rows.slice(safePage * pageSize, safePage * pageSize + pageSize), [rows, safePage, pageSize]);
  if (!rows.length) return <div className="empty">{empty}</div>;
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>{columns.map((column) => <th key={column.key}>{column.title}</th>)}</tr>
          </thead>
          <tbody>
            {slice.map((row, index) => (
              <tr key={index} className={onRow ? "clickable" : ""} onClick={() => onRow?.(row)}>
                {columns.map((column) => <td key={column.key}>{column.render(row)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span>共 {rows.length} 条</span>
        <span>
          <button className="btn-ghost" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>上一页</button>
          <span style={{ margin: "0 8px" }}>{safePage + 1} / {pages}</span>
          <button className="btn-ghost" disabled={safePage + 1 >= pages} onClick={() => setPage(safePage + 1)}>下一页</button>
        </span>
      </div>
    </>
  );
}
