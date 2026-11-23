const KEY = "mlps_project";

export function rememberedProject() {
  return localStorage.getItem(KEY) || "";
}

export function rememberProject(projectId: string) {
  if (projectId) localStorage.setItem(KEY, projectId);
}
