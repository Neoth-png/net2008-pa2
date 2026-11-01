
# test
import sys
import xml.etree.ElementTree as ET


def main():
    """Read the XML inventory and print each device ID."""

    
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    xml_filename = sys.argv[1]

    try:
        tree = ET.parse(xml_filename)
        root = tree.getroot()

        print("Site:", root.get("site"))

        # Find every device
        for device in root.findall("device"):
            device_id = device.get("id")
            print("Device ID:", device_id)

    except FileNotFoundError:
        print(f"Error: {xml_filename} was not found")
        sys.exit(1)


if __name__ == "__main__":
    main()