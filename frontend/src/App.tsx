import { Navigate, Route, Routes } from "react-router-dom";
import { savedUser } from "./api";
import AppLayout from "./layout/AppLayout";
import AdminPage from "./pages/AdminPage";
import AiEnginePage from "./pages/AiEnginePage";
import ClausesPage from "./pages/ClausesPage";
import DashboardPage from "./pages/DashboardPage";
import IntegrationsPage from "./pages/IntegrationsPage";
import LoginPage from "./pages/LoginPage";
import ProjectsPage from "./pages/ProjectsPage";
import TodosPage from "./pages/TodosPage";
import WorkspacePage from "./pages/WorkspacePage";

function Protected() {
  if (!savedUser()) return <Navigate to="/login" replace />;
  return <AppLayout />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Protected />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/projects/:projectId" element={<WorkspacePage />} />
        <Route path="/todos" element={<TodosPage />} />
        <Route path="/clauses" element={<ClausesPage />} />
        <Route path="/ai-engine" element={<AiEnginePage />} />
        <Route path="/integrations" element={<IntegrationsPage />} />
        <Route path="/admin" element={<AdminPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
