// src/index.ts — ClawGuard plugin entry point

import { AuditLog } from './audit-log'
import { setupPromptGuard } from './layers/prompt-guard'
import { setupOutputScanner } from './layers/output-scanner'
import { setupToolBlocker } from './layers/tool-blocker'
import { setupInputAuditor } from './layers/input-auditor'
import { setupSecurityGate } from './layers/security-gate'
import { registerSecurityCommand } from './commands/security'
import { registerAuditCommand } from './commands/audit'
import { registerHardenCommand } from './commands/harden'
import { registerScanPluginsCommand } from './commands/scan-plugins'
import { registerCheckUpdatesCommand } from './commands/check-updates'
import { DEFAULT_CONFIG, resolveLocale } from './types'
import type { ClawGuardConfig } from './types'

function mergeConfig(userConfig: Partial<ClawGuardConfig> | undefined): ClawGuardConfig {
  if (!userConfig) return { ...DEFAULT_CONFIG }

  // Validate mode
  const mode = userConfig.mode === 'audit' ? 'audit' : 'enforce'

  // Validate locale
  const validLocales = ['auto', 'zh', 'en'] as const
  const locale = validLocales.includes(userConfig.locale as any)
    ? (userConfig.locale as typeof validLocales[number])
    : DEFAULT_CONFIG.locale

  // Validate injectionThreshold: clamp to 0-100
  let threshold = userConfig.injectionThreshold ?? DEFAULT_CONFIG.injectionThreshold
  threshold = Math.max(0, Math.min(100, Math.round(threshold)))

  return {
    mode,
    locale,
    injectionThreshold: threshold,
    layers: {
      ...DEFAULT_CONFIG.layers,
      ...(userConfig.layers || {}),
    },
  }
}

export default {
  id: 'clawguard',

  register(api: any) {
    const config = mergeConfig(api.config)
    const log = new AuditLog(config)
    const enforce = config.mode === 'enforce'
    const locale = resolveLocale(config)

    const modeLabel = locale === 'zh'
      ? `模式: ${config.mode}`
      : `mode: ${config.mode}`
    api.logger.info(`[ClawGuard] Security plugin started (${modeLabel})`)

    // L1: Prompt Guard (before_prompt_build hook)
    if (config.layers.promptGuard) {
      setupPromptGuard(api, config, log)
    }

    // L2: Output Scanner (tool_result_persist hook, synchronous)
    if (config.layers.outputScanner) {
      setupOutputScanner(api, config, log, enforce)
    }

    // L3: Tool Blocker (before_tool_call hook)
    if (config.layers.toolBlocker) {
      setupToolBlocker(api, config, log, enforce)
    }

    // L4: Input Auditor + Injection Detection (before_tool_call + message_received)
    if (config.layers.inputAuditor) {
      setupInputAuditor(api, config, log, enforce)
    }

    // L5: Security Gate Tool (registerTool — defense in depth)
    if (config.layers.securityGate) {
      setupSecurityGate(api, config, log, enforce)
    }

    const enabled = Object.entries(config.layers)
      .filter(([, v]) => v)
      .map(([k]) => k)
    api.logger.info(`[ClawGuard] ${enabled.length} layers enabled: ${enabled.join(', ')}`)

    // Register slash commands (if registerCommand is available)
    if (api.registerCommand) {
      registerSecurityCommand(api, config)
      registerAuditCommand(api, config)
      registerHardenCommand(api, config)
      registerScanPluginsCommand(api, config)
      registerCheckUpdatesCommand(api, config)
      api.logger.info('[ClawGuard] 5 commands registered: /security /audit /harden /scan-plugins /check-updates')
    }

    log.write({
      level: 'INFO',
      layer: 'L1',
      action: 'allow',
      detail: `ClawGuard started with ${enabled.length} layers`,
    })
  },
}
