import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'

type PasswordFieldProps = {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  autoComplete: string
  minLength?: number
  helpText?: string
  error?: string
}

/** A password field with an accessible visibility toggle and inline feedback. */
export function PasswordField({ id, label, value, onChange, autoComplete, minLength, helpText, error }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false)
  const fieldName = label === 'Confirm password' || label === 'Confirm new password'
    ? 'confirmation password'
    : label.toLowerCase()
  const helpID = helpText ? `${id}-help` : undefined
  const errorID = error ? `${id}-error` : undefined
  const describedBy = [helpID, errorID].filter(Boolean).join(' ') || undefined

  return <div className="password-field"><label htmlFor={id}>{label}</label><div className="input-with-action"><input id={id} type={visible ? 'text' : 'password'} value={value} onChange={event => onChange(event.target.value)} autoComplete={autoComplete} minLength={minLength} required aria-invalid={error ? true : undefined} aria-describedby={describedBy} /><button type="button" aria-label={`${visible ? 'Hide' : 'Show'} ${fieldName}`} aria-controls={id} onClick={() => setVisible(show => !show)}>{visible ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>{helpText && <small id={helpID}>{helpText}</small>}{error && <small className="field-error" id={errorID}>{error}</small>}</div>
}
