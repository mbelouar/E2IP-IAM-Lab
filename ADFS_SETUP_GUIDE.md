# ADFS Configuration Guide - Fix MSIS7007 Error

## Problem

You're getting this error when clicking "Continue with SSO":

```
MSIS7007: The requested relying party trust 'http://192.168.64.1:8000/saml2/metadata/' is unspecified or unsupported.
```

## Root Cause

Your Django application isn't configured as a trusted relying party in ADFS.

## Solution: Configure ADFS Relying Party Trust

### Step 1: Access ADFS Management Console

1. Log into your ADFS server as an administrator
2. Open **ADFS Management** console
3. Navigate to **Trust Relationships** → **Relying Party Trusts**

### Step 2: Add New Relying Party Trust

1. Right-click **Relying Party Trusts** → **Add Relying Party Trust...**
2. Click **Start** in the wizard

### Step 3: Configure Data Source

**Option A: Import from Metadata URL (Recommended)**

1. Select **Import data about the relying party from a file**
2. Download your app's metadata first:
   ```bash
   curl -o django_metadata.xml http://192.168.64.1:8000/saml2/metadata/
   ```
3. Browse and select the downloaded `django_metadata.xml` file

**Option B: Manual Configuration**

1. Select **Enter data about the relying party manually**
2. **Display Name**: `Django SecureAuth Portal`
3. **Profile**: Select **AD FS profile**
4. **Certificate**: Skip (not required for testing)
5. **URL**: Check **Enable support for the SAML 2.0 WebSSO protocol**
   - Enter: `https://192.168.64.1:8000/custom-saml-acs/`
6. **Identifiers**: Add relying party trust identifier:
   - `http://192.168.64.1:8000/saml2/metadata/`

### Step 4: Configure Claim Rules

1. **Choose Issuance Authorization Rules**: Select **Permit all users to access this relying party**
2. **Configure Claims**: Check **Configure claims issuance policy for this application**
3. Click **Next** and **Close**

### Step 5: Add Claim Rules

1. In the **Claim Rules** tab, click **Add Rule...**
2. **Claim Rule Template**: Select **Send LDAP Attributes as Claims**
3. **Rule Name**: `Send User Attributes`
4. **Attribute Store**: Select **Active Directory**
5. **Mapping**:
   - **LDAP Attribute** → **Outgoing Claim Type**
   - `E-Mail-Addresses` → `E-Mail Address`
   - `Given-Name` → `Given Name`
   - `Surname` → `Surname`
   - `SAM-Account-Name` → `Name ID`

### Step 6: Add Name ID Rule

1. Click **Add Rule...** again
2. **Claim Rule Template**: Select **Transform an Incoming Claim**
3. **Rule Name**: `Transform Name ID`
4. **Incoming Claim Type**: `Name ID`
5. **Outgoing Claim Type**: `Name ID`
6. **Outgoing Name ID Format**: `Email`
7. **Pass through all claim values**: Checked

## Verification Steps

### 1. Check Relying Party Trust

- Verify the trust appears in ADFS Management
- Confirm the identifier matches: `http://192.168.64.1:8000/saml2/metadata/`

### 2. Test SSO Flow

1. Start your Django app: `./venv/bin/python manage.py runserver 0.0.0.0:8000`
2. Navigate to: `http://192.168.64.1:8000/login/`
3. Click **Continue with SSO**
4. Should redirect to ADFS login page without MSIS7007 error

### 3. Check Django Logs

Monitor Django logs for SAML response processing:

```bash
tail -f django.log
```

## Troubleshooting

### If Still Getting MSIS7007:

1. **Double-check Entity ID**: Must exactly match `http://192.168.64.1:8000/saml2/metadata/`
2. **Restart ADFS Service**:
   ```powershell
   Restart-Service -Name "adfssrv"
   ```
3. **Check ADFS Event Logs**: Windows Event Viewer → Applications and Services → AD FS → Admin

### If Getting Certificate Errors:

Your Django app is configured to ignore SSL validation for development:

```python
'disable_ssl_certificate_validation': True
'verify_ssl_cert': False
```

### If Users Can't Login After ADFS Redirect:

Check claim rules are properly configured and attributes are being sent.

### Common Login Issues:

Try different username formats:

1. `MYLAB\username`
2. `username@my-lab.local`
3. Just `username`

## Production Considerations

- Use HTTPS for all URLs
- Configure proper SSL certificates
- Enable signature verification
- Restrict claim rules to specific user groups
- Set up proper session timeouts

## Current Django Configuration

Your app is configured with:

- **Entity ID**: `http://192.168.64.1:8000/saml2/metadata/`
- **ACS URL**: `https://192.168.64.1:8000/custom-saml-acs/`
- **SLS URL**: `http://192.168.64.1:8000/saml2/ls/`
- **Metadata URL**: `http://192.168.64.1:8000/saml2/metadata/`
- **ADFS Server**: `192.168.64.3`
- **ADFS Domain**: `my-lab.local`
