/**
 * User Account Modal
 *
 * Allows users to:
 * - Change their display name
 * - Change their username
 * - Change their password
 */

import { useEffect, useState, type FormEvent } from 'react'
import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ChangePasswordModal } from '@/features/auth/ChangePasswordModal'
import { useAuth } from '@/features/auth/AuthContext'
import { apiClient, ApiError } from '@/lib/api/client'
import { useQueryClient } from '@tanstack/react-query'

interface UserAccountModalProps {
  isOpen: boolean
  onClose: () => void
}

export function UserAccountModal({ isOpen, onClose }: UserAccountModalProps) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [username, setUsername] = useState(user?.username || '')
  const [displayName, setDisplayName] = useState(user?.display_name || '')
  // SAUCEMON_HOOK_START
  const [companyName, setCompanyName] = useState(user?.company_name || '')
  const [primaryContact, setPrimaryContact] = useState(user?.primary_contact || '')
  // SAUCEMON_HOOK_END
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // SAUCEMON_HOOK_START
  useEffect(() => {
    setUsername(user?.username || '')
    setDisplayName(user?.display_name || '')
    setCompanyName(user?.company_name || '')
    setPrimaryContact(user?.primary_contact || '')
  }, [user])
  // SAUCEMON_HOOK_END

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccess(null)

    if (!username.trim()) {
      setError('Username is required')
      return
    }

    setIsSubmitting(true)

    try {
      // Update profile
      await apiClient.post('/v2/auth/update-profile', {
        username: username.trim(),
        display_name: displayName.trim() || null,
        // SAUCEMON_HOOK_START
        company_name: companyName.trim() || null,
        primary_contact: primaryContact.trim() || null,
        // SAUCEMON_HOOK_END
      })

      // Refetch user data
      await queryClient.invalidateQueries({ queryKey: ['auth', 'currentUser'] })

      setSuccess('Profile updated successfully!')
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 400) {
          setError(err.message || 'Username already taken')
        } else {
          setError('Failed to update profile. Please try again.')
        }
      } else {
        setError('Connection error. Please check if the backend is running.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!isOpen) return null

  return (
    <>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        onClick={onClose}
      >
        <div
          className="relative w-full max-w-md rounded-2xl border border-border bg-background p-6 shadow-lg"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-xl font-semibold">Account Settings</h2>
              <p className="text-sm text-muted-foreground mt-1">
                Manage your account information
              </p>
            </div>
            <button
              onClick={onClose}
              className="rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100"
            >
              <X className="h-4 w-4" />
              <span className="sr-only">Close</span>
            </button>
          </div>

          {/* Content */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Success/Error Messages */}
            {error && (
              <div className="rounded-lg border-l-4 border-danger bg-danger/10 p-3 text-sm text-danger">
                {error}
              </div>
            )}
            {success && (
              <div className="rounded-lg border-l-4 border-success bg-success/10 p-3 text-sm text-success">
                {success}
              </div>
            )}

            {/* Display Name */}
            <div>
              <label htmlFor="displayName" className="block text-sm font-medium mb-1">
                Display Name
              </label>
              <Input
                id="displayName"
                type="text"
                value={displayName}
                onChange={(e) => {
                  setDisplayName(e.target.value)
                  if (error || success) {
                    setError(null)
                    setSuccess(null)
                  }
                }}
                disabled={isSubmitting}
                placeholder="Optional friendly name"
              />
              <p className="text-xs text-muted-foreground mt-1">
                This is how your name will be displayed
              </p>
            </div>

            {/* SAUCEMON_HOOK_START */}
            {/* Company Name */}
            <div>
              <label htmlFor="companyName" className="block text-sm font-medium mb-1">
                Company Name
              </label>
              <Input
                id="companyName"
                type="text"
                value={companyName}
                onChange={(e) => {
                  setCompanyName(e.target.value)
                  if (error || success) {
                    setError(null)
                    setSuccess(null)
                  }
                }}
                disabled={isSubmitting}
                placeholder="Optional company or organization"
              />
            </div>

            {/* Primary Contact */}
            <div>
              <label htmlFor="primaryContact" className="block text-sm font-medium mb-1">
                Primary Contact
              </label>
              <Input
                id="primaryContact"
                type="text"
                value={primaryContact}
                onChange={(e) => {
                  setPrimaryContact(e.target.value)
                  if (error || success) {
                    setError(null)
                    setSuccess(null)
                  }
                }}
                disabled={isSubmitting}
                placeholder="Optional contact name or email"
              />
            </div>
            {/* SAUCEMON_HOOK_END */}

            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium mb-1">
                Username <span className="text-destructive">*</span>
              </label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value)
                  if (error || success) {
                    setError(null)
                    setSuccess(null)
                  }
                }}
                disabled={isSubmitting}
                required
              />
              <p className="text-xs text-muted-foreground mt-1">
                Used for logging in
              </p>
            </div>

            {/* Save Button */}
            <Button
              type="submit"
              disabled={isSubmitting}
              className="w-full"
            >
              {isSubmitting ? 'Saving...' : 'Save Changes'}
            </Button>
          </form>

          {/* Divider */}
          <div className="my-4 border-t border-border" />

          {/* Password Change Button */}
          <Button
            variant="outline"
            className="w-full"
            onClick={() => setShowPasswordModal(true)}
          >
            Change Password
          </Button>
        </div>
      </div>

      {/* Password Change Modal */}
      <ChangePasswordModal
        isOpen={showPasswordModal}
        isRequired={false}
        onClose={() => setShowPasswordModal(false)}
      />
    </>
  )
}
