
import json
import sys
import xml.etree.ElementTree as ET

import yaml


class AuditError(Exception):
    """Error."""


class Device:
    """represents a network device from the XML inventory."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        """Create a Device object."""

        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces

    def count_down_interfaces(self):
        """Return the number of interfaces with status 'down'."""

        count = 0

        for interface in self.interfaces:
            if interface["status"] == "down":
                count += 1

        return count

    def has_owner(self):
        """Return True if the device has a non-empty owner."""

        if self.owner is None:
            return False

        return bool(self.owner.strip())


def compare_versions(found, required):
    """Compare two dotted numeric version strings.

    Returns:
        -1 if found is older than required
         0 if versions are equal
         1 if found is newer than required
    """

    found_parts = found.split(".")
    required_parts = required.split(".")

    found_numbers = []

    for part in found_parts:
        found_numbers.append(int(part))

    required_numbers = []

    for part in required_parts:
        required_numbers.append(int(part))

    max_length = max(len(found_numbers), len(required_numbers))

    while len(found_numbers) < max_length:
        found_numbers.append(0)

    while len(required_numbers) < max_length:
        required_numbers.append(0)

    if found_numbers < required_numbers:
        return -1
    elif found_numbers > required_numbers:
        return 1
    else:
        return 0


def load_inventory(filename):
    """Load the XML inventory and return the site, devices, and skipped count."""

    try:
        tree = ET.parse(filename)
        root = tree.getroot()

    except FileNotFoundError as error:
        raise AuditError(f"Error: {filename} was not found") from error

    except ET.ParseError as error:
        raise AuditError(f"Error: {filename} contains invalid XML") from error

    site = root.get("site")

    devices = []
    skipped_devices = 0

    for element in root.findall("device"):

        device_id = element.get("id")

        # Skip devices without an ID
        if not device_id:
            skipped_devices += 1
            continue

        role = element.get("role")
        os_version = element.get("os")

        # Get the owner
        owner_element = element.find("owner")

        if owner_element is None:
            owner = None
        else:
            owner = owner_element.text

        # Get all interfaces
        interfaces = []

        for interface in element.findall("interface"):

            interface_name = interface.get("name")
            interface_status = interface.get("status")

            interfaces.append({
                "name": interface_name,
                "status": interface_status
            })

        device = Device(
            device_id,
            role,
            os_version,
            owner,
            interfaces
        )

        devices.append(device)

    return site, devices, skipped_devices


def load_policy(filename):
    """Load and validate the YAML policy file."""

    try:
        with open(filename, "r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)

    except FileNotFoundError as error:
        raise AuditError(f"Error: {filename} was not found") from error

    except yaml.YAMLError as error:
        raise AuditError(f"Error: {filename} contains invalid YAML") from error

    # An empty YAML file becomes None
    if policy is None:
        policy = {}

    if not isinstance(policy, dict):
        raise AuditError("Error: policy must be a YAML mapping")

    return policy


def check_device(device, policy):
    """Check one device against the policy and return its violations."""

    violations = []

    # Check minimum OS version
    min_os = policy.get("min_os")

    if min_os is not None:

        if device.role not in min_os:

            violations.append({
                "device": device.device_id,
                "type": "unknown_role",
                "role": device.role
            })

        else:

            required_version = min_os[device.role]

            if compare_versions(device.os_version, required_version) < 0:

                violations.append({
                    "device": device.device_id,
                    "type": "os_outdated",
                    "found": device.os_version,
                    "required": required_version
                })

    # Check owner
    if policy.get("require_owner") is True:

        if not device.has_owner():

            violations.append({
                "device": device.device_id,
                "type": "missing_owner"
            })

    # Check number of down interfaces
    if "max_down_interfaces" in policy:

        max_down = policy["max_down_interfaces"]
        down_count = device.count_down_interfaces()

        if down_count > max_down:

            violations.append({
                "device": device.device_id,
                "type": "too_many_down",
                "down": down_count
            })

    return violations


def build_report(site, devices, skipped_devices, policy):
    """Build the complete audit report dictionary."""

    roles = {}

    interfaces = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    violations = []
    violating_devices = set()

    for device in devices:

        # Count roles
        if device.role in roles:
            roles[device.role] += 1
        else:
            roles[device.role] = 1

        # Count interface statuses
        for interface in device.interfaces:

            status = interface["status"]

            if status == "up":
                interfaces["up"] += 1

            elif status == "down":
                interfaces["down"] += 1

            else:
                interfaces["other"] += 1

        # Check the device for violations
        device_violations = check_device(device, policy)

        if device_violations:

            violating_devices.add(device.device_id)

            for violation in device_violations:
                violations.append(violation)

    
    compliant = []

    for device in devices:

        if device.device_id not in violating_devices:
            compliant.append(device.device_id)

    compliant.sort()

    report = {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": compliant
    }

    return report


def write_report(report):
    """Write the audit report to audit.json."""

    try:
        with open("audit.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)

    except OSError as error:
        raise AuditError("Error: could not write audit.json") from error


def main():
    """Run the network inventory compliance audit."""

    # Check command-line arguments
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    xml_filename = sys.argv[1]
    policy_filename = sys.argv[2]

    try:
        # Load input files
        site, devices, skipped_devices = load_inventory(xml_filename)
        policy = load_policy(policy_filename)

        # Build the audit report
        report = build_report(
            site,
            devices,
            skipped_devices,
            policy
        )

        # Write JSON output
        write_report(report)

        # Print summary
        print(
            f"Audited {report['total_devices']} devices "
            f"with {len(report['violations'])} violations."
        )

    except AuditError as error:
        print(error)
        sys.exit(1)


if __name__ == "__main__":
    main()