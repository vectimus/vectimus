# Intune deployment

The `managed-settings.json` file is a template for deploying Vectimus as a managed Claude Code configuration via Microsoft Intune (or any MDM that can push JSON config files).

## Usage

1. Replace `https://vectimus.internal.example.com` with your Vectimus server URL.
2. Deploy via Intune as a managed settings file for Claude Code.
3. Set `VECTIMUS_API_KEY` in the managed environment.

The `allowManagedHooksOnly: true` setting prevents developers from overriding the governance hooks locally.
