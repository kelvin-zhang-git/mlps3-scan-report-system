# DefectDojo 去重字段说明。平台未部署时，本地 aggregate_findings 按 (asset, CVE/CWE, port) 合并。
DEDUPLICATION_ALGORITHM_PER_PARSER = {
    "Nmap Parser": ["hash_code"],
    "Nuclei Scan": ["title", "cwe", "endpoints"],
    "Trivy Scan": ["cve", "component_name", "file_path"],
}
