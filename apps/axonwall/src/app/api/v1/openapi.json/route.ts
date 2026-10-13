import { NextResponse } from 'next/server';

export async function GET() {
  const spec = {
    openapi: '3.1.0',
    info: {
      title: 'Axonwall Firewall REST API',
      version: '0.1.5',
      description: 'Declarative REST API for managing Axonwall Linux nftables firewalls, routing, services, and commit-confirm apply pipeline.',
    },
    servers: [
      {
        url: '/api/v1',
        description: 'Local Appliance API',
      },
    ],
    paths: {
      '/status': {
        get: {
          summary: 'Get operational status',
          description: 'Returns real-time status of the data plane, pending confirm status, uptime, and network interfaces.',
          responses: {
            '200': {
              description: 'Successful status response',
            },
          },
        },
      },
      '/apply': {
        post: {
          summary: 'Apply configuration changes',
          description: 'Atomically compiles and applies candidate ruleset to Linux nftables with commit-confirm protection.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    state: { type: 'object' },
                    confirmTimeoutSeconds: { type: 'integer', default: 120 },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Configuration applied and pending confirmation' },
            '400': { description: 'Validation error' },
          },
        },
      },
      '/confirm': {
        post: {
          summary: 'Confirm active configuration',
          description: 'Promotes candidate ruleset to last-known-good and cancels automatic rollback timer.',
          responses: {
            '200': { description: 'Configuration confirmed' },
          },
        },
      },
      '/rollback': {
        post: {
          summary: 'Rollback to last-known-good',
          description: 'Immediately reverts the active ruleset to the previous last-known-good bundle.',
          responses: {
            '200': { description: 'Rollback successful' },
          },
        },
      },
    },
  };

  return NextResponse.json(spec);
}
