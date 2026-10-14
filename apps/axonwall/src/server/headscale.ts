import http from 'http';

const HEADSCALE_SOCKET_PATH = process.env.HEADSCALE_SOCKET_PATH || '/run/headscale/headscale.sock';

/**
 * Make a request to the Headscale UNIX socket REST API.
 */
function headscaleRequest<T>(method: string, path: string, body?: any): Promise<T> {
  return new Promise((resolve, reject) => {
    const options: http.RequestOptions = {
      socketPath: HEADSCALE_SOCKET_PATH,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 5000,
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data) as T);
          } catch (e) {
            resolve(data as any);
          }
        } else {
          reject(new Error(`Headscale API error ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Headscale request timed out after 5000ms'));
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
  const data = await headscaleRequest<any>('GET', '/api/v1/user');
  return data.users || [];
}

export async function createUser(name: string) {
  const data = await headscaleRequest<any>('POST', '/api/v1/user', { name });
  return data.user;
}

export async function deleteUser(name: string) {
  return headscaleRequest<any>('DELETE', `/api/v1/user/${encodeURIComponent(name)}`);
}

// -----------------------------------------------------------------------------
// PreAuthKeys
// -----------------------------------------------------------------------------

export async function createPreAuthKey(user: string, reusable: boolean, ephemeral: boolean, expiration: string) {
  const data = await headscaleRequest<any>('POST', '/api/v1/preauthkey', {
    user,
    reusable,
    ephemeral,
    expiration, // e.g., '2023-12-31T23:59:59Z'
  });
  return data.preAuthKey;
}

export async function listPreAuthKeys(user?: string) {
  const params = user ? `?user=${encodeURIComponent(user)}` : '';
  const data = await headscaleRequest<any>('GET', `/api/v1/preauthkey${params}`);
  return data.preAuthKeys || [];
}

export async function expirePreAuthKey(user: string, key: string) {
  const data = await headscaleRequest<any>('POST', '/api/v1/preauthkey/expire', {
    user,
    key,
  });
  return data;
}

// -----------------------------------------------------------------------------
// Machines
// -----------------------------------------------------------------------------

export async function listMachines(user?: string) {
  const params = user ? `?user=${encodeURIComponent(user)}` : '';
  const data = await headscaleRequest<any>('GET', `/api/v1/machine${params}`);
  return data.machines || [];
}

export async function deleteMachine(machineId: string) {
  return headscaleRequest<any>('DELETE', `/api/v1/machine/${machineId}`);
}

export async function renameMachine(machineId: string, newName: string) {
  return headscaleRequest<any>('POST', `/api/v1/machine/${machineId}/rename/${encodeURIComponent(newName)}`);
}

export async function expireMachine(machineId: string) {
  return headscaleRequest<any>('POST', `/api/v1/machine/${machineId}/expire`);
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

export async function getMachineRoutes(machineId: string) {
  const data = await headscaleRequest<any>('GET', `/api/v1/machine/${machineId}/routes`);
  return data.routes || [];
}

export async function enableMachineRoutes(machineId: string, routes: string[]) {
  // Routes should be an array of string CIDRs, e.g. ["10.0.0.0/24"]
  const data = await headscaleRequest<any>('POST', `/api/v1/machine/${machineId}/routes`, { routes });
  return data.routes || [];
}
