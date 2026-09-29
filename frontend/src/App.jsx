import React from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider, RequireAuth } from './auth';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import {
  AcceptInvite, ForgotPassword, Login, ResetPassword, Signup, VerifyEmail,
} from './pages/AuthPages';
import {
  SettingsLayout, OrganizationSettings, MembersSettings, ApiKeysSettings,
  IntegrationsSettings, DataSettings, AccountSettings,
} from './pages/Settings';
import ChatTab from './components/ChatTab';
import DocumentTab from './components/DocumentTab';
import ReviewTab from './components/ReviewTab';
import InspectorTab from './components/InspectorTab';
import EvasionTab from './components/EvasionTab';
import TelemetryTab from './components/TelemetryTab';
import ApiHubTab from './components/ApiHubTab';
import ModelSpecsTab from './components/ModelSpecsTab';

function NotFound() {
  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1 className="auth-title">Page not found</h1>
        <p className="auth-subtitle">That address doesn't exist.</p>
        <Link className="btn btn-primary btn-block" to="/">Go home</Link>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/invite" element={<AcceptInvite />} />

          <Route path="/app" element={<RequireAuth><Dashboard /></RequireAuth>}>
            <Route index element={<Navigate to="assistant" replace />} />
            <Route path="assistant" element={<ChatTab />} />
            <Route path="inspector" element={<InspectorTab />} />
            <Route path="documents" element={<DocumentTab />} />
            <Route path="review" element={<ReviewTab />} />
            <Route path="adversarial" element={<EvasionTab />} />
            <Route path="audit" element={<TelemetryTab />} />
            <Route path="api" element={<ApiHubTab />} />
            <Route path="model" element={<ModelSpecsTab />} />
            <Route path="settings" element={<SettingsLayout />}>
              <Route index element={<Navigate to="organization" replace />} />
              <Route path="organization" element={<OrganizationSettings />} />
              <Route path="members" element={<MembersSettings />} />
              <Route path="api-keys" element={<ApiKeysSettings />} />
              <Route path="integrations" element={<IntegrationsSettings />} />
              <Route path="data" element={<DataSettings />} />
              <Route path="account" element={<AccountSettings />} />
            </Route>
          </Route>

          <Route path="*" element={<NotFound />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
