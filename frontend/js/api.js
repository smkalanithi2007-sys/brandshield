
const API_BASE = "http://127.0.0.1:8000";

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers
    }
  });

  const data = await response.json();

  if (!response.ok) {
    const message = typeof data.detail === "string"
      ? data.detail
      : "Request failed. Check the backend.";
    throw new Error(message);
  }

  return data;
}

const api = {
  analyze: (brand_name) =>
    apiRequest("/analyze", {
      method: "POST",
      body: JSON.stringify({ brand_name })
    }),

  brands: () => apiRequest("/brands"),

  addBrand: (name, domain) =>
    apiRequest("/brands", {
      method: "POST",
      body: JSON.stringify({ name, domain })
    }),

  deleteBrand: (id) =>
    apiRequest(`/brands/${encodeURIComponent(id)}`, {
      method: "DELETE"
    }),

  threats: () => apiRequest("/threats"),

  createDemoThreat: () =>
    apiRequest("/threats/demo", { method: "POST" }),

  updateThreat: (id, status) =>
    apiRequest(`/threats/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ status })
    }),

  reports: () => apiRequest("/reports")
};