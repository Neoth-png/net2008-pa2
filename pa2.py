
import sys
import xml.etree.ElementTree as ET


def main():
    """Read the XML inventory and count devices, roles and interfaces."""

    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    xml_filename = sys.argv[1]

    try:
        tree = ET.parse(xml_filename)
        root = tree.getroot()

        total_devices = 0
        skipped_devices = 0

        roles = {}

        interfaces = {
            "up": 0,
            "down": 0,
            "other": 0
        }

        print("Site:", root.get("site"))

        for device in root.findall("device"):

            device_id = device.get("id")

            if device_id is None:
                skipped_devices += 1
                continue

            total_devices += 1

            role = device.get("role")

            if role in roles:
                roles[role] += 1
            else:
                roles[role] = 1

            for interface in device.findall("interface"):

                status = interface.get("status")

                if status == "up":
                    interfaces["up"] += 1

                elif status == "down":
                    interfaces["down"] += 1

                else:
                    interfaces["other"] += 1

        print("\nTotal devices:", total_devices)
        print("Skipped devices:", skipped_devices)
        print("Roles:", roles)
        print("Interfaces:", interfaces)

    except FileNotFoundError:
        print(f"Error: {xml_filename} was not found")
        sys.exit(1)


if __name__ == "__main__":
    main()