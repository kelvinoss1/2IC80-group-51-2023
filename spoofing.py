import os
import netifaces

# Get a list of all available interfaces
available_interfaces = netifaces.interfaces()

print("Available interfaces:")
for i, interface in enumerate(available_interfaces, start=1):
    print("%d. %s" % (i, interface))

choice = raw_input("Enter 1 for ARP poisoning or 2 for DNS spoofing: ")

if choice == "1":
    command = "sudo python arp.py"
    while True:
        mode_input = raw_input("Enter the mode for arp.py (-m MODE): ")
        split_mode = mode_input.split()
        if len(split_mode) == 2 and split_mode[0] == "-m" and split_mode[1] in ["silent", "all-out"]:
            break
        else:
            print("Invalid input. Please provide the mode using the format: -m MODE (silent or all-out)")

    while True:
        interface_choice = raw_input("Enter the number corresponding to the desired interface: ")
        try:
            interface_index = int(interface_choice) - 1
            if interface_index >= 0 and interface_index < len(available_interfaces):
                interface = available_interfaces[interface_index]
                break
        except ValueError:
            pass
        print("Invalid choice. Please enter the number corresponding to the desired interface.")

    args = "%s %s -i %s" % (split_mode[0], split_mode[1], interface)

elif choice == "2":
    command = "sudo python dns.py"
    while True:
        interface_choice = raw_input("Enter the number corresponding to the desired interface: ")
        try:
            interface_index = int(interface_choice) - 1
            if interface_index >= 0 and interface_index < len(available_interfaces):
                interface = available_interfaces[interface_index]
                break
        except ValueError:
            pass
        print("Invalid choice. Please enter the number corresponding to the desired interface.")

    args = "-i %s" % interface


else:
    print("Invalid choice!")
    exit()

full_command = "{} {}".format(command, args)
os.system(full_command)
