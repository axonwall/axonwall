import { NextResponse } from 'next/server';
import { importFirewallConfig, detectFirewallType, type FirewallVendor } from '@axonwall/lib/import';
import { compileNftables } from '@axonwall/lib/compile/nft';
import { applyDesiredState } from '../../../../server/agent';

export async function POST(req: Request) {
  try {
    let configText = '';
    let vendor: FirewallVendor | undefined;
    let shouldApply = false;
    let confirmTimeoutSeconds = 120;

    const contentType = req.headers.get('content-type') || '';

    if (contentType.includes('multipart/form-data')) {
      const formData = await req.formData();
      const file = formData.get('file') as File | null;
      if (file) {
        configText = await file.text();
      } else {
        configText = (formData.get('config') as string) || '';
      }
      const vendorParam = formData.get('vendor') as string | null;
      if (vendorParam && vendorParam !== 'auto') {
        vendor = vendorParam as FirewallVendor;
      }
      shouldApply = formData.get('apply') === 'true' || formData.get('apply') === '1';
      const timeoutParam = formData.get('confirmTimeoutSeconds') as string | null;
      if (timeoutParam) {
        confirmTimeoutSeconds = Number.parseInt(timeoutParam, 10) || 120;
      }
    } else {
      const body = await req.json();
      configText = body.config || '';
      if (body.vendor && body.vendor !== 'auto') {
        vendor = body.vendor;
      }
      shouldApply = Boolean(body.apply);
      if (body.confirmTimeoutSeconds) {
        confirmTimeoutSeconds = Number(body.confirmTimeoutSeconds) || 120;
      }
    }

    if (!configText || configText.trim() === '') {
      return NextResponse.json(
        {
          status: 'error',
          error: 'No firewall configuration content provided. Send config text or upload a file.',
        },
        { status: 400 }
      );
    }

    // 1. Run Parser & Importer
    const report = importFirewallConfig(configText, vendor);

    // 2. Compile to Linux nftables
    const { nftScript } = compileNftables(report.state);

    // 3. Optional Apply to Live System
    let applyResult = null;
    if (shouldApply) {
      applyResult = await applyDesiredState(report.state, confirmTimeoutSeconds);
    }

    return NextResponse.json({
      status: 'ok',
      report,
      compiledNft: nftScript,
      applied: shouldApply,
      applyResult,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized')
      ? 401
      : err.message?.includes('Admin')
        ? 403
        : 400;

    return NextResponse.json(
      {
        status: 'error',
        error: err.message || 'Failed to process firewall configuration',
      },
      { status: statusCode }
    );
  }
}
