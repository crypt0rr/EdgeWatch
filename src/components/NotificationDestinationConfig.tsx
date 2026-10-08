import type { NotificationProvider as ProviderKind, NotificationProviderConfig } from '../api'

export type NotificationProvider = ProviderKind | 'url'

export type NotificationConfigDraft = {
  provider: NotificationProvider
  fields: Record<string, string>
}

export type NotificationCredentials =
  | { url: string }
  | { config: NotificationProviderConfig }

export const initialNotificationConfigDraft = (): NotificationConfigDraft => ({
  provider: 'smtp',
  fields: {},
})

export function credentialsFromNotificationDraft(draft: NotificationConfigDraft): NotificationCredentials | null {
  if (draft.provider === 'url') {
    const url = draft.fields.url?.trim() ?? ''
    return url ? { url } : null
  }
  return {
    config: {
      provider: draft.provider,
      fields: { ...draft.fields },
    },
  }
}

export function NotificationDestinationConfig({
  draft,
  onChange,
  idPrefix,
  allowBlankURL = false,
}: {
  draft: NotificationConfigDraft
  onChange: (draft: NotificationConfigDraft) => void
  idPrefix: string
  allowBlankURL?: boolean
}) {
  function changeProvider(provider: NotificationProvider) {
    onChange({ provider, fields: {} })
  }

  function changeField(name: string, value: string) {
    onChange({ ...draft, fields: { ...draft.fields, [name]: value } })
  }

  function field(name: string, label: string, options: { required?: boolean; type?: string; placeholder?: string; help?: string; min?: number; max?: number } = {}) {
    const id = `${idPrefix}-${name}`
    return <label key={name} htmlFor={id}>{label}
      <input
        id={id}
        type={options.type ?? 'text'}
        value={draft.fields[name] ?? ''}
        onChange={event => changeField(name, event.currentTarget.value)}
        required={options.required && !(allowBlankURL && draft.provider === 'url')}
        maxLength={4096}
        min={options.min}
        max={options.max}
        autoComplete="off"
        spellCheck={false}
        placeholder={options.placeholder}
      />
      {options.help && <small>{options.help}</small>}
    </label>
  }

  return <>
    <label htmlFor={`${idPrefix}-provider`}>Notification service
      <select
        id={`${idPrefix}-provider`}
        aria-label="Notification service"
        aria-describedby={`${idPrefix}-provider-help`}
        value={draft.provider}
        onChange={event => changeProvider(event.currentTarget.value as NotificationProvider)}
      >
        <option value="smtp">Email (SMTP)</option>
        <option value="discord">Discord webhook</option>
        <option value="ntfy">ntfy</option>
        <option value="url">Advanced Shoutrrr URL</option>
      </select>
      <small id={`${idPrefix}-provider-help`}>Choose a service, or use an existing Shoutrrr URL for other providers.</small>
    </label>
    {draft.provider === 'smtp' && <div className="settings-form notification-provider-fields">
      <div className="two-fields">
        {field('host', 'SMTP server', { required: true, placeholder: 'mail.example.com' })}
        {field('port', 'Port', { type: 'number', min: 1, max: 65535, placeholder: '25', help: 'Defaults to 25. StartTLS is enabled when the server supports it.' })}
      </div>
      <div className="two-fields">
        {field('from', 'From address', { required: true, placeholder: 'edgewatch@example.com' })}
        {field('to', 'Recipients', { required: true, placeholder: 'ops@example.com, team@example.com', help: 'Separate multiple email addresses with commas.' })}
      </div>
      <div className="two-fields">
        {field('username', 'SMTP username', { placeholder: 'Optional' })}
        {field('password', 'SMTP password', { type: 'password', placeholder: 'Optional' })}
      </div>
    </div>}
    {draft.provider === 'discord' && <div className="settings-form notification-provider-fields">
      {field('webhook_url', 'Discord webhook URL', { type: 'url', required: true, placeholder: 'https://discord.com/api/webhooks/…', help: 'Paste the webhook URL from your Discord channel integration.' })}
    </div>}
    {draft.provider === 'ntfy' && <div className="settings-form notification-provider-fields">
      <div className="two-fields">
        {field('server', 'ntfy server', { type: 'url', placeholder: 'https://ntfy.sh', help: 'Leave blank to use ntfy.sh.' })}
        {field('topic', 'Topic', { required: true, placeholder: 'edgewatch-alerts' })}
      </div>
      <div className="two-fields">
        {field('username', 'Username', { placeholder: 'Optional' })}
        {field('password', 'Password or token', { type: 'password', placeholder: 'Optional' })}
      </div>
    </div>}
    {draft.provider === 'url' && <div className="settings-form notification-provider-fields">
      {field('url', 'Shoutrrr URL', { type: 'url', required: true, placeholder: 'generic://host/path?disabletls=yes', help: 'The URL is encrypted after saving and cannot be read back.' })}
    </div>}
  </>
}
