// Fixed local ports, overridable when something else already uses them.
const port = (name: string, fallback: number) => Number(process.env[name] ?? fallback);

export const UI_PORT = port('BOSUN_E2E_UI_PORT', 18090);
export const PROXY_PORT = port('BOSUN_E2E_PROXY_PORT', 18080);
export const TARGET_PORT = port('BOSUN_E2E_TARGET_PORT', 18099);
