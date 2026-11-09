import { Compass } from 'lucide-react'
import { Link, Route, Routes } from 'react-router-dom'
import { EmptyState } from '@/components/EmptyState'
import { AppLayout } from '@/components/layout/AppLayout'
import { ModulePlaceholder } from '@/components/layout/ModulePlaceholder'
import SignInPage from '@/features/auth/SignInPage'
import SsoCallbackPage from '@/features/auth/SsoCallbackPage'
import ConnectPage from '@/features/connect/ConnectPage'
import DashboardPage from '@/features/dashboard/DashboardPage'
import DependenciesPage from '@/features/dependencies/DependenciesPage'
import HistoryPage from '@/features/history/HistoryPage'
import PqcPage from '@/features/pqc/PqcPage'
import { RequireAuth } from '@/lib/auth'
import SecretsPage from '@/features/secrets/SecretsPage'

/**
 * Rutas de la app. Para sumar una vista, reemplazar su ModulePlaceholder por
 * la página de features/<módulo>/ (PR revisado por el Módulo B).
 */
export default function App() {
  return (
    <Routes>
      <Route path="/sign-in/*" element={<SignInPage />} />
      <Route path="/sso-callback" element={<SsoCallbackPage />} />

      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route
          path="code"
          element={<ModulePlaceholder title="Código inseguro" owner="Módulo C" folder="features/code" />}
        />
        <Route path="secrets" element={<SecretsPage />} />
        <Route path="pqc" element={<PqcPage />} />
        <Route path="dependencies" element={<DependenciesPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="connect" element={<ConnectPage />} />
        <Route
          path="*"
          element={
            <EmptyState
              icon={Compass}
              title="Esta página no existe"
              description="Puede que el enlace esté roto o que la vista todavía no se haya publicado."
              action={
                <Link to="/" className="text-sm font-semibold text-civic underline decoration-civic/30 hover:decoration-civic">
                  Ir al dashboard
                </Link>
              }
              className="py-24"
            />
          }
        />
      </Route>
    </Routes>
  )
}
