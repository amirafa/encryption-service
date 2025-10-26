declare module "encryption-service" {
    export function EncryptionService(options?: {
        isolated?: boolean;
    }): import("./encryption-service").EncryptionServiceClass;
}
