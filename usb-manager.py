
import json
import shlex
import subprocess
import os.path

from pyudev import Context, Monitor
from jinja2 import FileSystemLoader, Environment


RULES_PATH = "./rules/91-usbdevices.rules"
INITIALIZATION_RULES_PATH = "./rules/90-usbdevices.rules"
FINALIZATION_RULES_PATH = "./rules/92-usbdevices.rules"
MODEL_PATH = "usbdevices.model"

DEBUG = True


def execute(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=None):
    command = shlex.split(command)

    try:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, cwd=cwd)
        std_out, std_err = process.communicate()

    except (subprocess.CalledProcessError, OSError) as error:
        return -1, error.strerror

    if stderr is None:  # if we want to ignore all errors
        # return all std_out data (if there is any),
        # use process.returncode to find out what was wrong
        return process.returncode, std_out

    if std_err:  # if we do not ignore errors
        return -1, std_err  # return the usual way

    return 0, std_out


class Singleton:
    instance = None

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls.instance, cls):
            cls.instance = object.__new__(cls, *args, **kwargs)

        return cls.instance


class Manager(Singleton):
    def __init__(self):

        self.model = {
            "system_devices": [],
            "whitelist_devices": [],
            "blacklist_devices": []
        }

        if os.path.exists(MODEL_PATH):
            self.load_model()

        else:
            for device in self.get_all_usb_devices():
                self.model["system_devices"].append(Manager.get_device_info(device))

            self.save_model()

    def load_model(self, path=MODEL_PATH):
        '''
        Load json-MODEL.
        :return: None
        '''

        with open(path, "r") as model_file:
            text = model_file.read()
            self.model = json.loads(text)

        self.save_udev_rules()

    def save_model(self):
        '''
        Save json-MODEL and save udev-rules.
        :return: None
        '''

        with open(MODEL_PATH, "w") as model_file:
            text = json.dumps(self.model, sort_keys=True, indent=4, separators=(',', ': '), ensure_ascii=False)
            model_file.write(text)

        self.save_udev_rules()

        # return_code, return_text = execute("udevadm control --reload-rules")
        # if 0 != return_code:
        #     sys.stderr.write("Error reloading udev-rules: {}".format(return_text))
        #
        # return_code, return_text = execute("udevadm trigger")
        # if 0 != return_code:
        #     sys.stderr.write("Error triggering udev-rules: {}".format(return_text))

    @staticmethod
    def save_initialization_rules(path=INITIALIZATION_RULES_PATH):
        '''
        Save udev-rules file that is used for initialization.
        :param path: path to initialization file
        :return: None
        '''

        file_loader = FileSystemLoader("templates")
        environment = Environment(loader=file_loader)
        template = environment.get_template("90")
        rules = template.render()

        with open(path, "w") as initialization_rules_file:
            initialization_rules_file.write(rules)

    @staticmethod
    def save_finalization_rules(path=FINALIZATION_RULES_PATH):
        '''
        Save udev-rules file that is used for finalization.
        :param path: path to finalization file
        :return: None
        '''

        file_loader = FileSystemLoader("templates")
        environment = Environment(loader=file_loader)
        template = environment.get_template("92")
        rules = template.render()

        with open(path, "w") as initialization_rules_file:
            initialization_rules_file.write(rules)

    def save_udev_rules(self):
        '''
        Save udev-rules file hat is used for usb-device authorization.
        :return: None
        '''

        self.save_initialization_rules()
        self.save_finalization_rules()

        file_loader = FileSystemLoader("templates")
        environment = Environment(loader=file_loader)
        template = environment.get_template("91")
        rules = template.render(data=self.model)

        with open(RULES_PATH, "w") as rules_file:
            rules_file.write(rules)

    @staticmethod
    def get_all_usb_devices():
        context = Context()

        devices = []
        for device in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            devices.append(device)

        return devices

    @staticmethod
    def get_removable_usb_devices():
        removables = []
        for device in Manager.get_all_usb_devices():
            if "DEVNAME" not in device:  # ignore unnamed devices
                continue

            if not Manager.is_device_removable(device):
                continue

            removables.append(device)

        return removables

    @staticmethod
    def get_device_attribute(device, attribute):
        value = device.attributes.get(str(attribute), None)
        if value is None:
            return ""

        if isinstance(value, bytes):
            value = value.decode("utf-8")

        value = str(value)
        value = " ".join(value.split("\n"))

        return value

    @staticmethod
    def get_device_info(device):

        # print "Properties:".upper()
        # for k, v in sorted(dict(device).items()):
        #     print "  @ {:35}   ==   {}".format(k, v)
        #
        # print "Attributes:".upper()
        # for attribute in device.attributes.available_attributes:
        #     print("  # {:35}   ==   {}".format(attribute, get_device_attribute(device, attribute)))

        info = {}
        info["path"] = device.get("DEVPATH", "")
        info["serial"] = Manager.get_device_attribute(device, "serial")
        info["vendor_id"] = Manager.get_device_attribute(device, "idVendor")
        info["product_id"] = Manager.get_device_attribute(device, "idProduct")

        return info

    @staticmethod
    def is_device_removable(device):
        attribute_value = Manager.get_device_attribute(device, "removable")
        attribute_value = str(attribute_value).lower()

        if "removable" == attribute_value:
            return True

        if "fixed" == attribute_value:
            return False

        elif "unknown" == attribute_value:
            parent = device.find_parent("usb")
            if not parent:
                return False
            else:
                return Manager.is_device_removable(parent)

        else:
            return False

    def list_section(self, section):
        section = str(section).lower()
        if section not in ["system_devices", "whitelist_devices", "blacklist_devices"]:
            raise ValueError("Either 'system', 'whitelist' or 'blacklist' is required, but not {}".format(section))

        return self.model[section]

    def list_sections(self):
        return self.model

    def add_device_to_section(self, section, device):
        if section not in self.model.keys():
            raise ValueError("Either 'system', 'whitelist' or 'blacklist' is required, but not {}".format(section))

        info = Manager.get_device_info(device)

        for current_section in self.model.keys():
            self.remove_device_from_section(current_section, device)

        self.model[section].append(info)
        self.save_model()

    def remove_device_from_section(self, section, device):
        if section not in self.model.keys():
            raise ValueError("Either 'system', 'whitelist' or 'blacklist' is required, but not {}".format(section))

        info = Manager.get_device_info(device)
        if info in self.model[section]:
            self.model[section].remove(info)
            self.save_model()

    def wait(self, on_new_device_attached_callback):
        context = Context()
        monitor = Monitor.from_netlink(context)
        monitor.filter_by("usb")

        while True:
            device = monitor.poll()

            if device.get("ACTION", "") == "remove":
                continue

            if device.get("DEVTYPE", "") != "usb_device":
                continue

            # system devices
            pattern = Manager.get_device_pattern(section="system_devices", device=device)
            if pattern in self.model["system_devices"]:
                print("System device plugged in: {}".format(pattern))
                continue

            # if device in blacklist
            pattern = Manager.get_device_pattern(section="blacklist_devices", device=device)
            if pattern in self.model["blacklist_devices"]:
                print("Blacklist-device plugged in: {}".format(pattern))
                continue

            # if device in whitelist
            pattern = Manager.get_device_pattern(section="whitelist_devices", device=device)
            if pattern in self.model["whitelist_devices"]:
                print("Whitelist-device plugged in: {}".format(pattern))
                continue

            on_new_device_attached_callback(device)

    def wait_for_new_devices(self):
        context = Context()
        monitor = Monitor.from_netlink(context)
        monitor.filter_by("usb")

        print("Waiting...")
        while True:
            device = monitor.poll()

            if device.get("ACTION", "") == "remove":
                continue

            if device.get("DEVTYPE", "") != "usb_device":
                continue

            while True:
                info = Manager.get_device_info(device)

                if "serial" in info:
                    text = "New device has been plugged in:\n{}.\nAdd to white list? [y/n] ".format(info)
                else:
                    text = "New device with unknown serial has been plugged in:\n{}.\nAdd to white list anyway? [y/n] ".format(info)

                choice = input(text)
                if "y" == str(choice).lower():
                    self.add_device_to_section(section="whitelist_devices", device=device)
                    print("New device has been added... Reattach device to use it.")
                    break

                elif "n" == str(choice).lower():
                    self.add_device_to_section(section="blacklist_devices", device=device)
                    print("New device has been blocked")
                    break

                else:
                    continue


if "__main__" == __name__:
    manager = Manager()
    manager.wait_for_new_devices()
