import yaml
import ipaddress
from jinja2 import Environment, FileSystemLoader


def netmask_filter(subnet):
    return str(ipaddress.ip_network(subnet).netmask)


def ciscowildcard_filter(value):
    if value == "any":
        return "any"
    net = ipaddress.ip_network(value)
    wildcard = ipaddress.ip_address(int(net.hostmask))
    return f"{net.network_address} {wildcard}"


env = Environment(loader=FileSystemLoader("templates"))
env.filters["netmask"] = netmask_filter
env.filters["ciscowildcard"] = ciscowildcard_filter

with open("network_inventory.yaml") as f:
    inventory = yaml.safe_load(f)

for device in inventory["devices"]:
    template_name = f"{device['type']}.j2"
    template = env.get_template(template_name)
    rendered = template.render(device=device)

    outfile = f"generated_configs/{device['name']}.cfg"
    with open(outfile, "w") as out:
        out.write(rendered)
    print(f"Generated: {outfile}")