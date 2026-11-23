import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { CveText } from "../components/CveText";
import DataTable from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";

type TodoPayload = {
  awaiting_approval?: { job_id: string; status: string; project_id?: string; project_name?: string } | null;
  awaiting_jobs?: Array<{ job_id: string; project_id: string; project_name?: string }>;
  pending_clauses: Array<{ assessment_id: string; clause_id: string; final_status: string; ai_rationale: string; project_id?: string; project_name?: string }>;
  manual_docs: Array<{ evidence_doc_id: string; clause_id: string; filename: string; note: string; reviewer: string; project_name?: string }>;
};

export default function TodosPage() {
  const [data, setData] = useState<TodoPayload | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<TodoPayload>("/api/todos").then(setData).catch((err: Error) => setError(err.message));
  }, []);
  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="card card-pad">正在读取待办...</div>;
  return (
    <>
      <div className="page-head"><div><h1>待办与审批</h1><p>需要确认的脱敏结果、仍待人工核对的条款，以及已经登记的制度证据。</p></div></div>
      <article className="card card-pad">
        <h2>待确认的脱敏结果</h2>
        {(data.awaiting_jobs || (data.awaiting_approval ? [data.awaiting_approval] : [])).length === 0 && <p className="muted" style={{ marginTop: 8 }}>目前没有等待确认的脱敏结果。</p>}
        {(data.awaiting_jobs || (data.awaiting_approval ? [data.awaiting_approval] : [])).map((job) => (
          <p key={job.job_id} style={{ marginTop: 8 }}>{job.project_name || "项目"} 的任务 {job.job_id} 还等人工确认，真实地址没有留在送审文本里。<Link to={`/projects/${job.project_id || ""}?tab=collect`}> 打开脱敏对照</Link></p>
        ))}
      </article>
      <article className="card">
        <div className="section-title"><h2>待人工条款</h2></div>
        <DataTable
          rows={data.pending_clauses || []}
          empty="最近一次已完成的评估里，没有仍待人工核查的条款。"
          columns={[
            { key: "project", title: "项目", render: (row) => row.project_name || "—" },
            { key: "id", title: "条款", render: (row) => row.clause_id },
            { key: "status", title: "状态", render: (row) => <StatusBadge value={row.final_status} /> },
            { key: "note", title: "说明", render: (row) => <CveText text={row.ai_rationale} /> },
          ]}
        />
      </article>
      <article className="card">
        <div className="section-title"><h2>已登记证据</h2></div>
        <DataTable
          rows={data.manual_docs || []}
          empty="制度文件和现场记录登记之后，会出现在这里。"
          columns={[
            { key: "project", title: "项目", render: (row) => row.project_name || "—" },
            { key: "clause", title: "条款", render: (row) => row.clause_id },
            { key: "file", title: "文件", render: (row) => row.filename },
            { key: "note", title: "说明", render: (row) => row.note },
            { key: "who", title: "登记人", render: (row) => row.reviewer },
          ]}
        />
      </article>
    </>
  );
}
