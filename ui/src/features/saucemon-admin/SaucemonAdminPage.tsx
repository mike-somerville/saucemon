import { useEffect, useState } from 'react'
import { apiClient, ApiError } from '@/lib/api/client'

interface SaucemonAdminOverviewResponse {
  mode: 'enabled'
  tenant: {
    tenant_id: string
    database_path: string
    deployment_model: string
  }
  users: {
    total: number
    admin: number
    user: number
    readonly: number
  }
}

export function SaucemonAdminPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [overview, setOverview] = useState<SaucemonAdminOverviewResponse | null>(null)

  useEffect(() => {
    const loadOverview = async () => {
      try {
        const data = await apiClient.get<SaucemonAdminOverviewResponse>('/saucemon/admin/overview')
        setOverview(data)
      } catch (err) {
        if (err instanceof ApiError) {
          setError(err.message)
        } else {
          setError('Failed to load Saucemon admin overview')
        }
      } finally {
        setIsLoading(false)
      }
    }

    loadOverview()
  }, [])

  return (
    <div className="min-h-screen bg-[#0a0e14]">
      <div className="border-b border-gray-800 bg-[#0d1117] px-3 py-4 sm:px-4 md:mt-0 md:px-6">
        <h1 className="mt-12 text-xl font-bold text-white md:mt-0 sm:text-2xl">Saucemon Admin</h1>
        <p className="mt-1 text-sm text-gray-400">
          Tenant administration and SaaS operations controls.
        </p>
      </div>

      <div className="container mx-auto max-w-5xl space-y-4 px-3 py-4 sm:px-4 sm:py-6 md:px-6">
        {isLoading && (
          <div className="rounded-lg border border-gray-800 bg-[#0d1117] p-4 text-sm text-gray-300">
            Loading Saucemon admin data...
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/30 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {overview && (
          <>
            <section className="rounded-lg border border-gray-800 bg-[#0d1117] p-4">
              <h2 className="text-base font-semibold text-white">Tenant Silo</h2>
              <div className="mt-3 grid gap-3 text-sm text-gray-300 sm:grid-cols-3">
                <div>
                  <p className="text-gray-500">Tenant ID</p>
                  <p className="font-medium text-white">{overview.tenant.tenant_id}</p>
                </div>
                <div>
                  <p className="text-gray-500">Database</p>
                  <p className="font-mono text-white">{overview.tenant.database_path}</p>
                </div>
                <div>
                  <p className="text-gray-500">Model</p>
                  <p className="font-medium text-white">{overview.tenant.deployment_model}</p>
                </div>
              </div>
            </section>

            <section className="rounded-lg border border-gray-800 bg-[#0d1117] p-4">
              <h2 className="text-base font-semibold text-white">Users</h2>
              <div className="mt-3 grid gap-3 text-sm text-gray-300 sm:grid-cols-4">
                <div>
                  <p className="text-gray-500">Total</p>
                  <p className="text-xl font-semibold text-white">{overview.users.total}</p>
                </div>
                <div>
                  <p className="text-gray-500">Admin</p>
                  <p className="text-xl font-semibold text-white">{overview.users.admin}</p>
                </div>
                <div>
                  <p className="text-gray-500">User</p>
                  <p className="text-xl font-semibold text-white">{overview.users.user}</p>
                </div>
                <div>
                  <p className="text-gray-500">Readonly</p>
                  <p className="text-xl font-semibold text-white">{overview.users.readonly}</p>
                </div>
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  )
}
