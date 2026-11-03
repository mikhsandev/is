export function planLegacyRedirectMigration(input: unknown, additionalHttpsUri?: string):
  | { error: string; httpsUris?: never; httpUris?: never }
  | { httpsUris: string[]; httpUris: string[]; error?: never };
