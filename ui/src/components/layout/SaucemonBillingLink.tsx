import React from 'react'
import { CreditCard } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SaucemonBillingLinkProps {
  isCollapsed: boolean
  onMobileClose?: (() => void) | undefined | null
}

const SAUCEMON_ADMIN_PORTAL_URL = 'https://localhost:8222'

export const SaucemonBillingLink: React.FC<SaucemonBillingLinkProps> = ({ isCollapsed, onMobileClose }) => {
  const tenantId = (import.meta.env.VITE_SAUCEMON_TENANT_ID as string | undefined)?.trim() || 'local'
  const billingUrl = `${SAUCEMON_ADMIN_PORTAL_URL}/billing?tenant_id=${encodeURIComponent(tenantId)}`

  return (
    <a
      href={billingUrl}
      target="_blank"
      rel="noopener noreferrer"
      onClick={() => onMobileClose?.()}
      className={cn(
        'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
        'text-muted-foreground hover:bg-surface-2 hover:text-foreground'
      )}
      title={isCollapsed ? 'Billing' : undefined}
    >
      <CreditCard className="h-5 w-5 flex-shrink-0" />
      <span className="md:hidden">Billing</span>
      {!isCollapsed && <span className="hidden md:inline">Billing</span>}
    </a>
  )
}
