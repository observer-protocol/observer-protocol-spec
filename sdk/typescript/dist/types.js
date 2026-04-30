/**
 * Observer Protocol SDK - Type Definitions
 */
// ── Errors ──────────────────────────────────────────────────
export class ObserverError extends Error {
    statusCode;
    detail;
    constructor(statusCode, detail) {
        super(`OP API Error ${statusCode}: ${detail}`);
        this.name = 'ObserverError';
        this.statusCode = statusCode;
        this.detail = detail;
    }
}
//# sourceMappingURL=types.js.map