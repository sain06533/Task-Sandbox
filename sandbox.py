import docker
import dpkt
from scapy.all import sniff
import time
import os

def pull_docker_image(image_name, tag):
    client = docker.from_env()
    try:
        image = client.images.pull(image_name, tag=tag)
        print(f"Image {image_name}:{tag} pulled successfully.")
        return image
    except docker.errors.APIError as e:
        print(f"Failed to pull image {image_name}:{tag}: {e}")
        return None

class MalwareAnalyzer:
    def __init__(self):
        self.client = docker.from_env()
        self.container = None

    def create_container(self, image):
        if not image:
            raise RuntimeError("Image not found. Please pull the image first.")
        volume = {"/mnt/analysis_file": {'bind': '/mnt/analysis_file', 'mode': 'ro'}}
        self.container = self.client.containers.run(image, detach=True, volumes=volume)

    def analyze_file(self, file_path):
        if not self.container:
            raise RuntimeError("Container not created. Call create_container() first.")
        command = f"ghidra {file_path}"
        result = self.container.exec_run(command, workdir='/mnt')
        return result.output.decode('utf-8')

    def stop_container(self):
        if self.container:
            self.container.stop()
            self.container.remove()

class NetworkAnalyzer:
    def __init__(self, interface):
        self.interface = interface

    def capture_packets(self, duration=10, output_file="network_capture.pcap"):
        packets = sniff(iface=self.interface, timeout=duration)
        with open(output_file, 'wb') as f:
            writer = dpkt.pcap.Writer(f)
            for packet in packets:
                writer.writepkt(bytes(packet))
        print(f"Network packets captured for {duration} seconds and saved to {output_file}.")

def get_file_path_from_location_file():
    """Read the file path from location.txt."""
    try:
        with open("location.txt", "r") as file:
            file_path = file.read().strip()
            return file_path
    except FileNotFoundError:
        print("Error: location.txt not found.")
        return None

# Use the correct interface name obtained from the list
interface_name = "Wi-Fi"  # Replace with the actual interface name if different

# Images to pull
images_to_pull = [
    {"name": "remnux/saltstack-tester", "tag": "latest"},
    {"name": "remnux/remnux-distro", "tag": "focal"}
]

pulled_image = pull_docker_image(images_to_pull[1]["name"], images_to_pull[1]["tag"])

if pulled_image:
    malware_analyzer = MalwareAnalyzer()
    malware_analyzer.create_container(pulled_image)

    file_path = get_file_path_from_location_file()
    if file_path:
        analysis_result = malware_analyzer.analyze_file(file_path)
        print("Analysis Result:")
        print(analysis_result)
        malware_analyzer.stop_container()

        network_analyzer = NetworkAnalyzer(interface=interface_name)
        network_analyzer.capture_packets(duration=10, output_file="malware_traffic.pcap")
    else:
        print("No valid file path found in location.txt.")
