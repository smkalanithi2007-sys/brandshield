async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers
    }
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    const detail = typeof data?.detail === "string"
      ? data.detail
      : `Request failed (${response.status}).`;
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }

  return data;
}

const api = {
  register: (email, password) =>
    apiRequest("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password })
    }),

  login: (email, password) =>
    apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    }),

  logout: () => apiRequest("/api/auth/logout", { method: "POST" }),
  me: () => apiRequest("/api/auth/me"),

  sources: () => apiRequest("/api/sources"),
  brands: () => apiRequest("/api/brands"),

  addBrand: (name, domain, monitoring_interval_hours, external_lookup_consent) =>
    apiRequest("/api/brands", {
      method: "POST",
      body: JSON.stringify({
        name,
        domain,
        monitoring_interval_hours,
        external_lookup_consent
      })
    }),

  deleteBrand: (id) =>
    apiRequest(`/api/brands/${encodeURIComponent(id)}`, {
      method: "DELETE"
    }),

  scheduleBrand: (id, interval_hours, external_lookup_consent = false) =>
    apiRequest(`/api/brands/${encodeURIComponent(id)}/schedule`, {
      method: "PATCH",
      body: JSON.stringify({ interval_hours, external_lookup_consent })
    }),

  scanBrand: (id) =>
    apiRequest(`/api/brands/${encodeURIComponent(id)}/scan`, {
      method: "POST"
    }),

  scan: (brand_name, domain, external_lookup_consent) =>
    apiRequest("/api/scans", {
      method: "POST",
      body: JSON.stringify({ brand_name, domain, external_lookup_consent })
    }),

  scans: () => apiRequest("/api/scans"),
  findings: () => apiRequest("/api/findings"),

  updateFinding: (id, status) =>
    apiRequest(`/api/findings/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status })
    }),

  reports: () => apiRequest("/api/reports")
};
