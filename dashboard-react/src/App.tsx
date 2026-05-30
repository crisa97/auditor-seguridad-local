import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider } from '@/context/AuthContext';
import { ProtectedRoute } from '@/components/auth';
import { Layout } from '@/components/layout';
import {
  LoginPage,
  DashboardPage,
  AnalysisPage,
  VulnerabilitiesPage,
  ApiKeysPage,
  UsersPage,
  ProfilePage,
} from '@/pages';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#232734',
              color: '#e4e6f0',
              border: '1px solid #373b52',
            },
            success: {
              iconTheme: { primary: '#2ecc71', secondary: '#232734' },
            },
            error: {
              iconTheme: { primary: '#e74c3c', secondary: '#232734' },
            },
          }}
        />
        <Routes>
          <Route path="/dashboard/login" element={<LoginPage />} />

          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="analysis" element={<AnalysisPage />} />
            <Route
              path="vulnerabilities"
              element={
                <ProtectedRoute requiredRoles={['admin']}>
                  <VulnerabilitiesPage />
                </ProtectedRoute>
              }
            />
            <Route path="api-keys" element={<ApiKeysPage />} />
            <Route path="profile" element={<ProfilePage />} />
            <Route
              path="admin/users"
              element={
                <ProtectedRoute requiredRoles={['admin']}>
                  <UsersPage />
                </ProtectedRoute>
              }
            />
          </Route>

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
