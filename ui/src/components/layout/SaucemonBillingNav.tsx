import React from 'react';
import { NavLink } from 'react-router-dom';
import { CreditCard } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SaucemonBillingNavProps {
  isCollapsed: boolean;
  onMobileClose?: (() => void) | undefined | null; // Be hyper-explicit for strict mode
}

export const SaucemonBillingNav: React.FC<SaucemonBillingNavProps> = ({ isCollapsed, onMobileClose }) => {
  return (
    <NavLink
      to="/billing"
      onClick={() => onMobileClose?.()}
      className={({ isActive }) =>
        cn(
          'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
          'hover:bg-surface-2 hover:text-foreground',
          isActive
            ? 'bg-surface-2 text-foreground before:absolute before:left-0 before:top-0 before:h-full before:w-0.5 before:rounded-r before:bg-primary'
            : 'text-muted-foreground'
        )
      }
      title={isCollapsed ? 'Billing' : undefined}
    >
      <CreditCard className="h-5 w-5 flex-shrink-0" />
      <span className="md:hidden">Billing</span>
      {!isCollapsed && <span className="hidden md:inline">Billing</span>}
    </NavLink>
  );
};