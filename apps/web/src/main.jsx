import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import RouteTitle from "./components/RouteTitle";

// Auth pages
import Login from "./pages/Login.jsx";
import Signup from "./pages/Signup.jsx";

// User pages
import Dashboard from "./pages/Dashboard.jsx";
import App from "./App.jsx"; // Chat interface
import Issues from "./pages/Issues.jsx";
import Reports from "./pages/Reports.jsx";
import Settings from "./pages/Settings.jsx";
import Alerts from "./pages/Alerts.jsx";
import Activity from "./pages/Activity.jsx";
import Policies from "./pages/Policies.jsx";
import Assets from "./pages/Assets.jsx";
import Validation from "./pages/Validation.jsx";
import Remediation from "./pages/remediation.jsx";
import Integrations from "./pages/Integrations.jsx";
import Agents from "./pages/Agents.jsx";

// Admin pages
import AdminDashboard from "./pages/AdminDashboard.jsx";
import UserManagement from "./pages/UserManagement.jsx";
import Admin from "./pages/Admin.jsx"; // Document Manager
import Analytics from "./pages/Analytics.jsx";
import SystemSettings from "./pages/SystemSettings.jsx";

// Styles
import "./index.css";
import "./App.css";
import './styles/theme.css'
import "./styles/theme.css";
import "./styles/Sidebar.css";
import "./styles/responsive.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <RouteTitle />
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />

          {/* ============ USER ROUTES ============ */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/chat"
            element={
              <ProtectedRoute>
                <App />
              </ProtectedRoute>
            }
          />
          <Route
            path="/issues"
            element={
              <ProtectedRoute>
                <Issues />
              </ProtectedRoute>
            }
          />
          <Route
            path="/assets"
            element={
              <ProtectedRoute>
                <Assets />
              </ProtectedRoute>
            }
          />
          <Route
            path="/remediation"
            element={
              <ProtectedRoute>
                <Remediation />
              </ProtectedRoute>
            }
          />
          <Route
            path="/validation"
            element={
              <ProtectedRoute>
                <Validation />
              </ProtectedRoute>
            }
          />
             <Route
            path="/integrations"
            element={
              <ProtectedRoute>
                <Integrations />
              </ProtectedRoute>
            }
          />
          <Route
            path="/agents"
            element={
              <ProtectedRoute>
                <Agents />
              </ProtectedRoute>
            }
          />
          <Route
            path="/activity"
            element={
              <ProtectedRoute>
                <Activity />
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Reports />
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <Alerts />
              </ProtectedRoute>
            }
          />
          <Route
            path="/policies"
            element={
              <ProtectedRoute>
                <Policies />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />

          {/* ============ ADMIN ROUTES ============ */}
          <Route
            path="/admin/dashboard"
            element={
              <ProtectedRoute adminOnly={true}>
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/users"
            element={
              <ProtectedRoute adminOnly={true}>
                <UserManagement />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/issues"
            element={
              <ProtectedRoute adminOnly={true}>
                <Issues />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/remediation"
            element={
              <ProtectedRoute adminOnly={true}>
                <Remediation />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/documents"
            element={
              <ProtectedRoute adminOnly={true}>
                <Admin />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/analytics"
            element={
              <ProtectedRoute adminOnly={true}>
                <Analytics />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/agents"
            element={
              <ProtectedRoute adminOnly={true}>
                <Agents />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/settings"
            element={
              <ProtectedRoute adminOnly={true}>
                <SystemSettings />
              </ProtectedRoute>
            }
          />

          {/* Legacy route redirects */}
          <Route path="/vulnerabilities" element={<Navigate to="/issues" replace />} />
          <Route path="/admin/vulnerabilities" element={<Navigate to="/admin/issues" replace />} />

          {/* Redirect root based on auth status */}
          <Route path="/" element={<Navigate to="/login" replace />} />

          {/* Catch all - redirect to login */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);