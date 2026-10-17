export declare function listUsers(): Promise<{
    id: any;
    name: any;
    createdAt: string;
}[]>;
export declare function createUser(name: string): Promise<{
    id: any;
    name: any;
    createdAt: string;
}>;
export declare function deleteUser(name: string): Promise<any>;
export declare function createPreAuthKey(user: string | number, reusable: boolean, ephemeral: boolean, expiration?: string): Promise<{
    id: any;
    key: any;
    reusable: any;
    ephemeral: any;
    expiration: string | undefined;
    user: any;
}>;
export declare function listPreAuthKeys(user?: string): Promise<{
    id: any;
    key: any;
    reusable: any;
    ephemeral: any;
    used: any;
    expiration: string | undefined;
    createdAt: string | undefined;
    user: any;
}[]>;
export declare function expirePreAuthKey(user: string, key: string): Promise<any>;
export declare function listMachines(user?: string): Promise<{
    id: any;
    name: any;
    ipAddresses: any;
    user: any;
    lastSeen: string | null;
    online: any;
    routes: any;
}[]>;
export declare function deleteMachine(machineId: string | number): Promise<any>;
export declare function renameMachine(machineId: string | number, newName: string): Promise<any>;
export declare function expireMachine(machineId: string | number): Promise<any>;
export declare function getMachineRoutes(machineId: string | number): Promise<any[]>;
export declare function enableMachineRoutes(machineId: string | number, routes: string[]): Promise<any>;
//# sourceMappingURL=headscale.d.ts.map