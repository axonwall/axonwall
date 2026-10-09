export declare function listUsers(): Promise<any>;
export declare function createUser(name: string): Promise<any>;
export declare function deleteUser(name: string): Promise<any>;
export declare function createPreAuthKey(user: string, reusable: boolean, ephemeral: boolean, expiration: string): Promise<any>;
export declare function listPreAuthKeys(user?: string): Promise<any>;
export declare function expirePreAuthKey(user: string, key: string): Promise<any>;
export declare function listMachines(user?: string): Promise<any>;
export declare function deleteMachine(machineId: string): Promise<any>;
export declare function renameMachine(machineId: string, newName: string): Promise<any>;
export declare function expireMachine(machineId: string): Promise<any>;
export declare function getMachineRoutes(machineId: string): Promise<any>;
export declare function enableMachineRoutes(machineId: string, routes: string[]): Promise<any>;
//# sourceMappingURL=headscale.d.ts.map