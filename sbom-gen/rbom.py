#!/usr/bin/env python3
"""
RBOM Generates SBOM if not present, then processes through VEX analysis
"""

import json
import subprocess
import csv
import sys
import os
import time
from datetime import datetime
import math
import shutil

global component_count
global sbom
global vuln
global fixed
global affected
component_count = 0
vuln = 0
fixed = 0
affected = 0
sbom = 0

# Timing registry: filled as each stage completes
_stage_timings = {}

def _record_time(stage, elapsed):
    """Save a stage elapsed time."""
    _stage_timings[stage] = round(elapsed, 2)

def _save_timing_report():
    """Write timing-report.json so rbom_evaluate.py reads real values."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "stages": {
            stage: {"seconds": secs, "minutes": round(secs / 60, 2)}
            for stage, secs in _stage_timings.items()
        },
        "total_seconds": round(sum(_stage_timings.values()), 2),
        "total_minutes": round(sum(_stage_timings.values()) / 60, 2),
    }
    with open("timing-report.json", "w") as f:
        json.dump(report, f, indent=2)
    return report

def generate_sbom(target="/"):
    """  Module 1: Generate SBOM using Syft"""
    global component_count
    print("    SBOM Gen...")
    # print("───────────────────────────────────────────────────────────────────────")
    print(f"      Target: {target}")
    
    # Check if Syft is installed
    try:
        result = subprocess.run(["syft", "version"], capture_output=True, check=True)
        # print(f"  Syft version: {result.stdout.decode().strip().split()[1]}")
    except:
        print(" Syft not installed. Install with:")
        print("   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin")
        return False
    
    # Prepare target
    if not target.startswith("dir:"):
        target = f"dir:{target}"
    
    print("    Generating SBOM of target...")
    # print(f"  Running: syft {target} -o cyclonedx-json")
    print("      (This may take 30 sec to 15 minutes for scanning the whole Linux system...)")
    # print("      (If you have external drives, unmount them...)")
    print()
    
    # Run Syft
    cmd = ["syft", target, "-o", "cyclonedx-json", "-q"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Write SBOM to file
        with open("sbom.json", "w") as f:
            f.write(result.stdout)
        
        # Parse to count components
        sbom_data = json.loads(result.stdout)
        component_count = len(sbom_data.get('components', []))
        
        print(f"  SBOM generated: sbom.json")
        print(f"  Components found: {component_count}")
        print()
        # changefilepermission()
        return True
        
    except subprocess.CalledProcessError as e:
        print(f" SBOM generation failed: {e.stderr}")
        print(e.stderr)
        return False
    except Exception as e:
        print(f" Error: {e}")
        return False

def changefilepermission():
    # Check if sbom.json exists
    if os.path.exists('sbom.json'):
        # Get file stats
        stat_info = os.stat('sbom.json')
        
        # Check if owned by root (UID 0)
        if stat_info.st_uid == 0:
            # print("    File is owned by root, changing permissions...")
            
            # Get actual user's ID when running with sudo
            uid = int(os.environ.get('SUDO_UID', os.getuid()))
            gid = int(os.environ.get('SUDO_GID', os.getgid()))
            
            # Change ownership
            os.chown('sbom.json', uid, gid)
            
            # Set permissions to rwxrwxrwx (777)
            os.chmod('sbom.json', 0o777)
            
            # print("Changed ownership and permissions for sbom.json")
        else:
            pass
            # print("    sbom.json File is not owned by root, no changes needed")
    else:
        print("    sbom.json not found")
    return


def run_grype_scan(sbom_file, output_file):
    """Run Grype scan on SBOM and generate CSV report"""
    global component_count
    print("  [*] Running vulnerability scan...")
    print(f"        SBOM: {sbom_file}")
    
    # Check if Grype is installed
    try:
        subprocess.run(["grype", "version"], capture_output=True, check=True)
    except:
        print(" Grype not installed. Install with:")
        print("   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin")
        return False
    
    # List Existing SBOM Components
    with open('sbom.json') as f:
        sbom = json.load(f)

    count = len(sbom.get('components', []))
    component_count = count
    print(f"        Components: {count}")

    
    # Run Grype
    print()
    print("  Scanning... This may take 2-10 minutes...")
    # print("     (This may take 5-10 minutes...)")
    cmd = ["grype", f"sbom:{sbom_file}", "-o", "json", "-q"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        grype_data = json.loads(result.stdout)
        
        # Write intermediate JSON (keep both names for compatibility)
        with open("grype-report.json", "w") as f:
            json.dump(grype_data, f, indent=2)
        with open("vuln-complete-report.json", "w") as f:
            json.dump(grype_data, f, indent=2)
        
        # Convert to CSV
        convert_grype_to_csv(grype_data, output_file)
        print(f"      Vulnerability scan complete: {output_file}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f" Grype scan failed: {e.stderr}")
        return False
    except Exception as e:
        print(f" Error: {e}")
        return False

def convert_grype_to_csv(grype_data, csv_file):
    """Convert Grype JSON to CSV format"""
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Installed', 'Fixed-In', 'Type', 'Vulnerability', 'Severity', 'URL'])
        
        if 'matches' in grype_data:
            for match in grype_data['matches']:
                artifact = match.get('artifact', {})
                vuln = match.get('vulnerability', {})
                
                name = artifact.get('name', '')
                version = artifact.get('version', '')
                pkg_type = artifact.get('type', '')
                vuln_id = vuln.get('id', '')
                severity = vuln.get('severity', 'Unknown')
                
                # Get fixed version
                fixed_in = ''
                if 'fix' in vuln and 'versions' in vuln['fix']:
                    fixed_in = ', '.join(vuln['fix']['versions'])
                
                # Get URL
                url = ''
                if 'dataSource' in vuln:
                    url = vuln['dataSource']
                
                writer.writerow([name, version, fixed_in, pkg_type, vuln_id, severity, url])
    
    # print(f"    Vulnerability report conversion JSON to CSV format: {csv_file}")
    print(f"      Vulnerability report converted  to csv format")

def process_vex(grype_csv, vex_csv):
    """Process Grype CSV through VEX analysis"""
    print()
    print("  [*] Processing through VEX databases...")
    
    vex_records = []
    
    with open(grype_csv, 'r') as f:
        reader = csv.DictReader(f)
        count = 0
        
        for row in reader:
            count += 1
            # if count % 100 == 0:
            if count % 10000 == 0:
                print(f"        Processed: {count} vulnerabilities")
            
            # Extract fields
            name = row['Name']
            version = row['Installed']
            fixed_in = row['Fixed-In']
            pkg_type = row['Type']
            vuln_id = row['Vulnerability']
            severity = row['Severity']
            url = row['URL']
            
            # VEX Analysis
            vex_status = analyze_vex_status(fixed_in, severity)
            exploitability = analyze_exploitability(severity, pkg_type)
            cvss_score = estimate_cvss(severity)
            data_source = extract_data_source(url)
            description = f"{vuln_id} vulnerability in {name} package ({severity} severity)"
            action = generate_action(vex_status, severity, fixed_in)
            last_updated = datetime.now().isoformat()
            
            vex_records.append({
                'Vulnerability': vuln_id,
                'Package': name,
                'Version': version,
                'Severity': severity,
                'CVSS Score': cvss_score,
                'Fixed Version': fixed_in,
                'VEX Status': vex_status,
                'Exploitability': exploitability,
                'Data Source': data_source,
                'Description': description,
                'URLs': url,
                'Action Required': action,
                'Last Updated': last_updated
            })
    
    # Write VEX CSV
    with open(vex_csv, 'w', newline='') as f:
        fieldnames = ['Vulnerability', 'Package', 'Version', 'Severity', 'CVSS Score', 
                     'Fixed Version', 'VEX Status', 'Exploitability', 'Data Source', 
                     'Description', 'URLs', 'Action Required', 'Last Updated']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(vex_records)

    # Also write as report.csv for backward compatibility
    with open('report.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(vex_records)
    
    print()
    print(f"  VEX analysis complete: {count} vulnerabilities processed")
    vuln = count
    print(f"  VEX report: {vex_csv}")
    return True

def analyze_vex_status(fixed_in, severity):
    """Analyze VEX status"""
    if fixed_in and fixed_in not in ['', 'N/A', 'none']:
        return 'fixed'
    if severity.upper() in ['CRITICAL', 'HIGH']:
        return 'under_investigation'
    return 'affected'

def analyze_exploitability(severity, pkg_type):
    """Analyze exploitability"""
    sev = severity.upper()
    if 'lib' in pkg_type.lower():
        if sev == 'CRITICAL':
            return 'High'
        if sev == 'HIGH':
            return 'Medium'
        return 'Low'
    
    if sev == 'CRITICAL':
        return 'High'
    if sev == 'HIGH':
        return 'Medium'
    if sev == 'MEDIUM':
        return 'Low'
    return 'Low'

def estimate_cvss(severity):
    """Estimate CVSS score from severity"""
    mapping = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.5,
        'LOW': 3.0,
        'NEGLIGIBLE': 0.5,
        'UNKNOWN': 0.0
    }
    return mapping.get(severity.upper(), 0.0)

def extract_data_source(url):
    """Extract data source from URL"""
    if 'nvd.nist.gov' in url:
        return 'NVD'
    if 'github.com' in url:
        return 'GitHub Security Advisory'
    if 'ubuntu.com' in url:
        return 'Ubuntu Security'
    if 'debian.org' in url:
        return 'Debian Security'
    return 'Grype Database'

def generate_action(vex_status, severity, fixed_in):
    """Generate action recommendation"""
    if vex_status == 'fixed':
        if fixed_in:
            return f"Update to version {fixed_in}"
        return "Apply available patch"
    if vex_status == 'under_investigation':
        return "Monitor for updates; apply workarounds if available"
    if severity.upper() in ['CRITICAL', 'HIGH']:
        return "Urgent: Review and mitigate; monitor for patches"
    return "Review and assess impact; monitor for patches"

def calculate_security_score(vex_csv):
    global sbom
    global vuln
    global fixed
    global affected
    
	
    """Calculate security score from VEX report"""
    global component_count
    print(" Calculating security score...")
    
    # Count by severity and VEX status
    counts = {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'negligible': 0, 'unknown': 0,
        'fixed': 0, 'affected': 0, 'under_investigation': 0
    }
    total_vulns = 0
    total_cvss = 0.0
    
    with open(vex_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_vulns += 1
            severity = row['Severity'].lower()
            vex_status = row['VEX Status'].lower()
            cvss = float(row['CVSS Score'])
            total_cvss += cvss
            
            if severity in counts:
                counts[severity] += 1
            else:
                counts['unknown'] += 1
            
            if vex_status in counts:
                counts[vex_status] += 1
    
    # Calculate weighted risk
    weights = {'critical': 10.0, 'high': 7.5, 'medium': 4.0, 'low': 1.0, 'negligible': 0.1, 'unknown': 2.5}
    vex_multipliers = {'fixed': 0.1, 'under_investigation': 0.7, 'affected': 1.0}
    
    base_risk = sum(counts[sev] * weights[sev] for sev in ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'])
    

    if total_vulns > 0:
        risk_per_vuln = base_risk / total_vulns
        weighted_avg_mult = sum(counts[status] * vex_multipliers[status]
                                 for status in ['fixed', 'affected', 'under_investigation']) / total_vulns
        weighted_risk = risk_per_vuln * weighted_avg_mult   # risk density, bounded roughly [0, 10]
        avg_cvss = total_cvss / total_vulns
    else:
        weighted_risk = 0
        avg_cvss = 0
    
    # Calculate score (0-100)
    # Using exponential decay formula for realistic scoring
    # Formula: Score = 100 * exp(-weighted_risk / scale_factor)
    # weighted_risk is now a per-vulnerability risk DENSITY in ~[0, 10] (severity weight
    # range), not a raw summed count, so scale_factor must be of the same order as the
    # weight scale. scale_factor = 3.0 provides a full-range distribution over that scale:
    # - Density 0.0-0.6 -> Score 82-100 (Grade A-B)
    # - Density 0.6-1.2 -> Score 67-82  (Grade C-B)
    # - Density 1.2-2.4 -> Score 45-67  (Grade E-D)
    # - Density >2.4    -> Score 0-45   (Grade F-E)
    
    if weighted_risk == 0:
        score = 100
    else:
        scale_factor = 3.0  # density-scale decay constant, see bugfix note above
        score = int(100 * math.exp(-weighted_risk / scale_factor))
        score = max(0, min(100, score))  # Ensure 0-100 range
    
    # Determine grade and risk level
    if score >= 90:
        grade, risk_level = 'A', 'MINIMAL'
    elif score >= 80:
        grade, risk_level = 'B', 'LOW'
    elif score >= 70:
        grade, risk_level = 'C', 'MEDIUM'
    elif score >= 60:
        grade, risk_level = 'D', 'HIGH'
    elif score >= 50:
        grade, risk_level = 'E', 'HIGH'
    else:
        grade, risk_level = 'F', 'CRITICAL'
    
    # Create report
    report = {
        'overall_score': score,
        'grade': grade,
        'weighted_risk': round(weighted_risk, 4),
        'risk_level': risk_level,
        'sbom components found': component_count,
        'total_vulnerabilities': total_vulns,
        'critical_count': counts['critical'],
        'high_count': counts['high'],
        'medium_count': counts['medium'],
        'low_count': counts['low'],
        'negligible_count': counts['negligible'],
        'unknown_count': counts['unknown'],
        'fixed_count': counts['fixed'],
        'affected_count': counts['affected'],
        'under_investigation_count': counts['under_investigation'],
        'average_cvss': round(avg_cvss, 2),
        
        'timestamp': datetime.now().isoformat(),
        'report_file': vex_csv
    }
    
    # Write JSON
    with open('security-score.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # add to scion staticInfoConfig.json variable
    sbom = component_count
    vuln = total_vulns
    fixed = counts['fixed']
    affected = counts['affected']

    # print(f"SBOM: {sbom} components ")
    # print(f"Vulnerabilities: {vuln} found ")
    # print(f"Fixed Vulnerabilities: {fixed} ")
    # print(f"Affected Vulnerabilities: {affected}  ")

    
    # Write text report
    text_report = f"""╔═══════════════════════════════════════════════════════════════════════╗
║                     RBOM SECURITY SCORE REPORT                        ║
╚═══════════════════════════════════════════════════════════════════════╝

[*] OVERALL SECURITY SCORE: {score}/100
[*] SECURITY GRADE: {grade}
[*] RISK LEVEL: {risk_level}
[*] Weighted Risk Density: {weighted_risk:.4f}

[*] SBOM components found: {component_count}
[*] Total Vulnerabilities: {total_vulns}
  🔴 Critical: {counts['critical']}
  🟠 High: {counts['high']}
  🟡 Medium: {counts['medium']}
  🟢 Low: {counts['low']}
  ⚪ Negligible: {counts['negligible']}
  ❓ Unknown: {counts['unknown']}

[*] VEX Status Analysis:
  ✅ Fixed: {counts['fixed']} ({counts['fixed']/total_vulns*100:.1f}%)
  ⚠️ Affected: {counts['affected']} ({counts['affected']/total_vulns*100:.1f}%)
  🔍 Under Investigation: {counts['under_investigation']} ({counts['under_investigation']/total_vulns*100:.1f}%)

[*]  Average CVSS Score: {avg_cvss:.2f}/10.0

[*]  Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Report Files:
  - VEX Report: {vex_csv}
  - JSON Score: security-score.json
  - Text Report: security-score.txt

═══════════════════════════════════════════════════════════════════════
"""
    
    with open('security-score.txt', 'w') as f:
        f.write(text_report)
    print(f"\n  [*] Security Score: {score}/100 (Grade {grade})")
    print(f"  [*] Risk Level: {risk_level}")
    print(f"  [*] Vulnerabilities: Critical={counts['critical']}, High={counts['high']}, Medium={counts['medium']}, Low={counts['low']}")
    print(f"  [*] VEX Status: Fixed={counts['fixed']}, Affected={counts['affected']}, Under Investigation={counts['under_investigation']}\n")
    
    return True

def generate_scion_config(score_file):
    """Generate SCION configuration"""
    global component_count
    print("  [*] Generating SCION network configuration...")
    
    with open(score_file, 'r') as f:
        score_data = json.load(f)
    
    min_score = 70
    config = {
        'security_score': score_data['overall_score'],
        'min_score': min_score,
        'policy_mode': 'balanced',
        'timestamp': datetime.now().isoformat(),
        'enabled': score_data['overall_score'] >= min_score,
        'grade': score_data['grade'],
        'risk_level': score_data['risk_level']
    }
    
    with open('scion-config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    # print(f"  Current Score: {config['security_score']}/100 (Grade {config['grade']})")
    # print(f"  Minimum Required: {min_score}/100")
    
    if config['enabled']:
        print()
    else:
        print(f"      WARNING: Score below minimum threshold!")
    
    print(f"      SCION config: scion-config.json\n")
    return True

def generate_scion_staticInfoConfig():
    global component_count
    global sbom
    global vuln
    global fixed
    global affected
    
    print("  [*] Generating SCION RBOM network configuration...")

    # Define the JSON data
    data = {
        "Latency": {
            "1": {
                "Inter": "30ms",
                "Intra": {
                    "1": "100000h",
                    "2": "10ms"
                }
            },
            "2": {
                "Inter": "40ms"
            }
        },
        "CarbonIntensity": {
            "1": {
                "Inter": 780,
                "Intra": {
                    "2": 300
                }
            },
            "2": {
                "Inter": 400
            }
        },
        "Sbom": {
            "1": {
                "Inter": sbom,
                "Intra": {
                    "2": sbom
                }
            },
            "2": {
                "Inter": sbom
            }
        },
        "Vuln": {
            "1": {
                "Inter": vuln,
                "Intra": {
                    "2": vuln
                }
            },
            "2": {
                "Inter": vuln
            }
        },
        "Fixed": {
            "1": {
                "Inter": fixed,
                "Intra": {
                    "2": fixed
                }
            },
            "2": {
                "Inter": fixed
            }
        },
        "Affected": {
            "1": {
                "Inter": affected,
                "Intra": {
                    "2": affected
                }
            },
            "2": {
                "Inter": affected
            }
        },
        "Hops": {
            "1": {
                "Intra": {
                    "2": 2
                }
            }
        },
        "Note": "asdf"
    }

    # Create the file
    with open('staticInfoConfig.json', 'w') as f:
        json.dump(data, f, indent=2)

    print("  [*] Created staticInfoConfig.json")

    # Copy to SCION AS directory if it exists
    scion_dst = os.path.join(os.path.dirname(os.path.abspath('.')),
                             'scion-sbom', 'gen', 'ASff00_0_110')
    if os.path.isdir(scion_dst):
        shutil.copy('staticInfoConfig.json', scion_dst)
        print(f"  [*] Copied staticInfoConfig to {scion_dst}")
    else:
        print("  [*] staticInfoConfig.json saved to current directory")

    return True


def main():
    print("╔═══════════════════════════════════════════════════════════════════════╗")
    print("║                                RBOM                                   ║")
    print("║                                                                       ║")
    print("╚═══════════════════════════════════════════════════════════════════════╝")
    print()
    global component_count
    print("=" * 71)
    print("  MODULE 1: SBOM Generation")
    print("=" * 71)
    print()
    
    # Check for existing SBOM
    sbom_file = 'sbom.json'
    sbom_exists = os.path.exists(sbom_file)
    
    if sbom_exists:
        # SBOM exists - ask user what to do
        print(f"  [*] Found existing SBOM: {sbom_file}")
        print("    Options:")
        print("      1. Use existing SBOM (skip Module 1)")
        print("      2. Regenerate SBOM (run Module 1)")
        print()
        
        while True:
            choice = input("  [*] Select option (1 or 2): ").strip()
            if choice in ['1', '2']:
                break
            print("  Invalid choice. Please enter 1 or 2.")
        
        if choice == '2':
            print()
            target = input("  [*] Enter target directory (Press Enter for default: /): ").strip()
            if not target:
                target = "/"
            print()
            
            # print("=" * 71)
            # print("  MODULE 1: SBOM Generation")
            # print("=" * 71)
            # print()
            
            _t0 = time.time()
            if not generate_sbom(target):
                sys.exit(1)
            _elapsed = time.time() - _t0
            _record_time("Syft SBOM scan", _elapsed)
            print(f"  [*] Module 1 elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
        else:
            print(f"  Skipping Module 1 - Using existing SBOM\n")
            _record_time("Syft SBOM scan", 0.0)  # stage skipped; recorded as 0
            _record_time("Syft SBOM scan", 0.0)  # skipped
    else:
        # No SBOM - automatically generate it
        print("  [*] No existing SBOM found - will generate new SBOM")
        print()
        
        target = input("    Enter target directory to scan (default: /): ").strip()
        if not target:
            target = "/"
        print()
        
        # print("=" * 71)
        # print("  MODULE 1: SBOM Generation")
        # print("=" * 71)
        # print()
        
        _t0 = time.time()
        if not generate_sbom(target):
            sys.exit(1)
        _elapsed = time.time() - _t0
        _record_time("Syft SBOM scan", _elapsed)
        print(f"  [*] Module 1 elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
    
    # Module 2: Grype Scan + VEX
    print("=" * 71)
    print("  MODULE 2: Vulnerability Scanning + VEX Analysis")
    print("=" * 71)
    print()
    
    grype_csv = 'grype-report.csv'
    vex_csv   = 'vex-report.csv'

    
    _t0 = time.time()
    if not run_grype_scan(sbom_file, grype_csv):
        sys.exit(1)
    _elapsed = time.time() - _t0
    _record_time("Grype CVE match", _elapsed)
    print(f"  [*] Grype scan elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
    
    _t0 = time.time()
    if not process_vex(grype_csv, vex_csv):
        sys.exit(1)
    _elapsed = time.time() - _t0
    _record_time("VEX enrichment", _elapsed)
    print(f"  [*] VEX enrichment elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
    
    # Module 3: Security Score
    print()
    print("=" * 71)
    print("  MODULE 3: Security Score Calculation")
    print("=" * 71)
    print()
    
    _t0 = time.time()
    if not calculate_security_score(vex_csv):
        sys.exit(1)
    _elapsed = time.time() - _t0
    _record_time("Score computation", _elapsed)
    print(f"  [*] Module 3 elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
    
    # Module 4: SCION
    print("=" * 71)
    print("  MODULE 4: SCION Network Integration")
    print("=" * 71)
    print()
    
    # if not generate_scion_config('security-score.json'):
    #     sys.exit(1)

    _t0 = time.time()
    if not generate_scion_staticInfoConfig():
        sys.exit(1)
    _elapsed = time.time() - _t0
    _record_time("SCION config injection", _elapsed)
    print(f"  [*] Module 4 elapsed: {_elapsed:.1f}s ({_elapsed/60:.2f} min)")
    
    # Summary
    print("=" * 71)
    print(" RBOM Completed Successfully!")
    print("=" * 71)
    print()
    print(f"  [*] SBOM components found:          {component_count}")
    print()
    # Save and display timing report
    timing = _save_timing_report()
    print()
    print("=" * 71)
    print("  PIPELINE TIMING SUMMARY")
    print("=" * 71)
    print(f"  {'Stage':<30} {'Seconds':>10} {'Minutes':>10}")
    print("  " + "-" * 52)
    for stage, data in timing["stages"].items():
        print(f"  {stage:<30} {data['seconds']:>10.1f} {data['minutes']:>10.2f}")
    print("  " + "-" * 52)
    print(f"  {'TOTAL':<30} {timing['total_seconds']:>10.1f} {timing['total_minutes']:>10.2f}")
    print()

    print(f"  [*] Generated Files:")
    print(f"    SBOM:                         {sbom_file}")
    print(f"    Grype Raw CSV:                {grype_csv}")
    print(f"    VEX Report:                   {vex_csv}")
    print(f"    Grype JSON:                   grype-report.json")
    print(f"    Security Score (JSON):        security-score.json")
    print(f"    Security Score (text):        security-score.txt")
    print(f"    Timing Report:                timing-report.json")
    print(f"    SCION Config:                 staticInfoConfig.json")
    print()

if __name__ == '__main__':
    main()
