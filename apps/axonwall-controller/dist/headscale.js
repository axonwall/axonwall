import http from 'http';
const HEADSCALE_SOCKET_PATH = process.env.HEADSCALE_SOCKET_PATH || '/run/headscale/headscale.sock';
/**
 * Make a request to the Headscale UNIX socket REST API.
 */
function headscaleRequest(method, path, body) {
    return new Promise((resolve, reject) => {
        const options = {
            socketPath: HEADSCALE_SOCKET_PATH,
            path: path,
            method: method,
            timeout: 5000,
            headers: {
                'Content-Type': 'application/json',
            },
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch (e) {
                        resolve(data);
                    }
                }
                else {
                    reject(new Error(`Headscale API error ${res.statusCode}: ${data}`));
                }
            });
        });
        req.on('timeout', () => {
            req.destroy();
            reject(new Error(`Headscale request timed out after 5000ms: ${path}`));
        });
        req.on('error', (e) => {
            reject(new Error(`Failed to connect to Headscale: ${e.message}`));
        });
        if (body) {
            req.write(JSON.stringify(body));
        }
        req.end();
    });
}
// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------
export async function listUsers() {
    const data = await headscaleRequest('GET', '/api/v1/user');
    return data.users || [];
}
export async function createUser(name) {
    const data = await headscaleRequest('POST', '/api/v1/user', { name });
    return data.user;
}
export async function deleteUser(name) {
    return headscaleRequest('DELETE', `/api/v1/user/${encodeURIComponent(name)}`);
}
// -----------------------------------------------------------------------------
// PreAuthKeys
// -----------------------------------------------------------------------------
export async function createPreAuthKey(user, reusable, ephemeral, expiration) {
    const data = await headscaleRequest('POST', '/api/v1/preauthkey', {
        user,
        reusable,
        ephemeral,
        expiration, // e.g., '2023-12-31T23:59:59Z'
    });
    return data.preAuthKey;
}
export async function listPreAuthKeys(user) {
    const params = user ? `?user=${encodeURIComponent(user)}` : '';
    const data = await headscaleRequest('GET', `/api/v1/preauthkey${params}`);
    return data.preAuthKeys || [];
}
export async function expirePreAuthKey(user, key) {
    const data = await headscaleRequest('POST', '/api/v1/preauthkey/expire', {
        user,
        key,
    });
    return data;
}
// -----------------------------------------------------------------------------
// Machines
// -----------------------------------------------------------------------------
export async function listMachines(user) {
    const params = user ? `?user=${encodeURIComponent(user)}` : '';
    const data = await headscaleRequest('GET', `/api/v1/machine${params}`);
    return data.machines || [];
}
export async function deleteMachine(machineId) {
    return headscaleRequest('DELETE', `/api/v1/machine/${machineId}`);
}
export async function renameMachine(machineId, newName) {
    return headscaleRequest('POST', `/api/v1/machine/${machineId}/rename/${encodeURIComponent(newName)}`);
}
export async function expireMachine(machineId) {
    return headscaleRequest('POST', `/api/v1/machine/${machineId}/expire`);
}
// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------
export async function getMachineRoutes(machineId) {
    const data = await headscaleRequest('GET', `/api/v1/machine/${machineId}/routes`);
    return data.routes || [];
}
export async function enableMachineRoutes(machineId, routes) {
    // Routes should be an array of string CIDRs, e.g. ["10.0.0.0/24"]
    const data = await headscaleRequest('POST', `/api/v1/machine/${machineId}/routes`, { routes });
    return data.routes || [];
}
