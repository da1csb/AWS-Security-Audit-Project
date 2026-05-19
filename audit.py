import boto3
from datetime import datetime

findings = []

def check_iam_mfa():
    iam = boto3.client('iam')
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']

        if len(mfa_devices) == 0:
            findings.append({
                'severity': 'HIGH',
                'service': 'IAM',
                'resource': username,
                'issue': 'User has no MFA device configured',
                'recommendation': 'Enable MFA on this IAM user immediately'
            })
            print(f'[HIGH] IAM: {username} has no MFA')
        else:
            print(f'[OK]   IAM: {username} has MFA')


def check_s3_public_access():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        name = bucket['Name']
        try:
            block = s3.get_public_access_block(Bucket=name)
            config = block['PublicAccessBlockConfiguration']

            all_blocked = all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ])

            if not all_blocked:
                findings.append({
                    'severity': 'CRITICAL',
                    'service': 'S3',
                    'resource': name,
                    'issue': 'Block Public Access is not fully enabled',
                    'recommendation': 'Enable all 4 Block Public Access settings'
                })
                print(f'[CRITICAL] S3: {name} — public access not fully blocked')
            else:
                print(f'[OK]       S3: {name} — public access blocked')

        except Exception as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                findings.append({
                    'severity': 'CRITICAL',
                    'service': 'S3',
                    'resource': name,
                    'issue': 'No public access block configuration exists',
                    'recommendation': 'Enable all 4 Block Public Access settings immediately'
                })
                print(f'[CRITICAL] S3: {name} — no public access block config found')
            else:
                print(f'[SKIP]     S3: {name} — could not check ({error_code})')


def check_security_groups():
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups()['SecurityGroups']

    risky_ports = {22: 'SSH', 3389: 'RDP'}

    for sg in sgs:
        sg_name = sg.get('GroupName', sg['GroupId'])

        for rule in sg['IpPermissions']:
            from_port = rule.get('FromPort', -1)

            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if from_port == -1:
                        findings.append({
                            'severity': 'CRITICAL',
                            'service': 'EC2',
                            'resource': sg_name,
                            'issue': 'All inbound traffic allowed from 0.0.0.0/0',
                            'recommendation': 'Restrict inbound rules to specific ports and IPs'
                        })
                        print(f'[CRITICAL] SG: {sg_name} — all traffic open to internet')
                    elif from_port in risky_ports:
                        port_name = risky_ports[from_port]
                        findings.append({
                            'severity': 'HIGH',
                            'service': 'EC2',
                            'resource': sg_name,
                            'issue': f'{port_name} (port {from_port}) open to 0.0.0.0/0',
                            'recommendation': f'Restrict {port_name} to trusted IPs only'
                        })
                        print(f'[HIGH] SG: {sg_name} — {port_name} open to internet')


def check_cloudtrail():
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=False)['trailList']

    if not trails:
        findings.append({
            'severity': 'CRITICAL',
            'service': 'CloudTrail',
            'resource': 'account',
            'issue': 'No CloudTrail trail configured in this region',
            'recommendation': 'Create a multi-region CloudTrail trail logging to S3'
        })
        print('[CRITICAL] CloudTrail: no trail found in this region')
        return

    for trail in trails:
        trail_name = trail['Name']
        status = ct.get_trail_status(Name=trail['TrailARN'])

        if not status.get('IsLogging', False):
            findings.append({
                'severity': 'CRITICAL',
                'service': 'CloudTrail',
                'resource': trail_name,
                'issue': 'Trail exists but logging is stopped',
                'recommendation': 'Start logging on this trail immediately'
            })
            print(f'[CRITICAL] CloudTrail: {trail_name} — logging is OFF')
        else:
            print(f'[OK]       CloudTrail: {trail_name} — logging active')

        if not trail.get('IsMultiRegionTrail', False):
            findings.append({
                'severity': 'MEDIUM',
                'service': 'CloudTrail',
                'resource': trail_name,
                'issue': 'Trail is single-region only',
                'recommendation': 'Enable multi-region trail to cover all AWS regions'
            })
            print(f'[MEDIUM]   CloudTrail: {trail_name} — single-region only')


def generate_html_report(findings):
    severity_colors = {
        'CRITICAL': '#A32D2D',
        'HIGH':     '#854F0B',
        'MEDIUM':   '#185FA5',
        'LOW':      '#3B6D11'
    }
    severity_bg = {
        'CRITICAL': '#FCEBEB',
        'HIGH':     '#FAEEDA',
        'MEDIUM':   '#E6F1FB',
        'LOW':      '#EAF3DE'
    }

    rows = ''
    for f in findings:
        color = severity_colors.get(f['severity'], '#333')
        bg    = severity_bg.get(f['severity'], '#fff')
        rows += f"""
        <tr>
          <td><span style="background:{bg};color:{color};padding:2px 8px;
              border-radius:99px;font-size:12px;font-weight:500">
              {f['severity']}</span></td>
          <td>{f['service']}</td>
          <td><code style="font-size:12px">{f['resource']}</code></td>
          <td>{f['issue']}</td>
          <td style="color:#3B6D11">{f['recommendation']}</td>
        </tr>"""

    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high     = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium   = sum(1 for f in findings if f['severity'] == 'MEDIUM')
    now      = datetime.now().strftime('%Y-%m-%d %H:%M')

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>AWS Security Audit Report</title>
<style>
  body {{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a1a}}
  h1 {{font-size:22px;font-weight:500;margin-bottom:4px}}
  .meta {{font-size:13px;color:#666;margin-bottom:28px}}
  .stats {{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:28px}}
  .stat {{background:#f8f8f6;border-radius:8px;padding:16px;text-align:center}}
  .stat-num {{font-size:28px;font-weight:500}}
  .stat-label {{font-size:12px;color:#888;margin-top:2px}}
  table {{width:100%;border-collapse:collapse;font-size:13px}}
  th {{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;
       letter-spacing:.06em;color:#888;border-bottom:1px solid #e8e8e4}}
  td {{padding:10px 12px;border-bottom:0.5px solid #f0f0ec;vertical-align:top}}
  tr:hover td {{background:#fafaf8}}
</style>
</head><body>
<h1>AWS Security Audit Report</h1>
<div class="meta">Generated: {now}</div>
<div class="stats">
  <div class="stat"><div class="stat-num" style="color:#A32D2D">{critical}</div>
    <div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#854F0B">{high}</div>
    <div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#185FA5">{medium}</div>
    <div class="stat-label">Medium</div></div>
</div>
<table>
  <tr><th>Severity</th><th>Service</th><th>Resource</th>
      <th>Issue</th><th>Recommendation</th></tr>
  {rows}
</table>
</body></html>"""

    with open('report.html', 'w') as f:
        f.write(html)
    print('\nReport saved: report.html — open it in your browser')


# run all 4 checks
print('--- IAM ---')
check_iam_mfa()
print('\n--- S3 ---')
check_s3_public_access()
print('\n--- Security Groups ---')
check_security_groups()
print('\n--- CloudTrail ---')
check_cloudtrail()
print(f'\n=== TOTAL FINDINGS: {len(findings)} ===')
generate_html_report(findings)