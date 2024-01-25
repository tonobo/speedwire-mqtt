
import time
from struct import *
import socket
import logging
import json
import os
import paho.mqtt.client as mqtt
import random

MY_SYSTEMID    = int(random.random() * 100)                # random number, has to be different from any device in local network
MY_SERIAL      = int(random.random() * 1000000000)            # random number, has to be different from any device in local network
ANY_SYSTEMID   = 0xFFFF                # 0xFFFF is any susyid
ANY_SERIAL     = 0xFFFFFFFF            # 0xFFFFFFFF is any serialnumber
SMA_PKT_HEADER = "534D4100000402A000000001"
SMA_ESIGNATURE = "00106065"

# UDP_IPB = "239.12.255.254"
# MESSAGE = bytes.fromhex('534d4100000402a0ffffffff0000002000000000')

COMMAND_LIST = {
    # name,                     [command,    first,      last      ]
    "login":                    [0xFFFD040C, 0x00000007, 0x00000384],
    "logout":                   [0xFFFD010E, 0xFFFFFFFF, 0x00000000],
    "info":                     [0x58000200, 0x00821E00, 0x008220FF],
    "energy":                   [0x54000200, 0x00260100, 0x002622FF],
    "power_ac_total":           [0x51000200, 0x00263F00, 0x00263FFF],
    "ac_voltage_current":       [0x51000200, 0x00464800, 0x004655FF],
    "dc_voltage_current":       [0x53800200, 0x00451F00, 0x004521FF],
    "dc_power":                 [0x53800200, 0x00251E00, 0x00251EFF],
    "ac_power":                 [0x51000200, 0x00464000, 0x004642FF],
    "temp":                     [0x51000200, 0x00465700, 0x004657FF],
    "freq":                     [0x52000200, 0x00237700, 0x002377FF],
}

SMA_INV_TYPE = {
    9099: "STP 6000TL-20",
    9102: "STP 9000TL-20",
}

SMA_INV_CLASS = {
    8000: "Any Device",
    8001: "Solar Inverter",
    8002: "Wind Turbine Inverter",
    8007: "Batterie Inverter",
    8033: "Consumer",
    8064: "Sensor System in General",
    8065: "Electricity meter",
    8128: "Communication product",
}

class smaError(Exception):
    pass

class SMA_SPEEDWIRE:
    def __init__(self, host, password="0000", logger=None):
        self.host = host
        self.port = 9522
        self.password = password
        self.pkt_id = 0
        self.my_id = MY_SYSTEMID.to_bytes(2, byteorder='little') + MY_SERIAL.to_bytes(4, byteorder='little')
        self.target_id = ANY_SYSTEMID.to_bytes(2, byteorder='little') + ANY_SERIAL.to_bytes(4, byteorder='little')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3.0)
        self.retry = 2

        self.serial = None
        self.inv_class = None
        self.inv_type = None

        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        
    def _packet(self, cmd):
        self.pkt_id += 1                                                                                # increase packet counter
        commands = COMMAND_LIST[cmd]
        sep2 = bytes([0x00, 0x00])                                                                      # separator for default commands
        sep4 = bytes([0x00, 0x00, 0x00, 0x00])
        data = sep4                                                                                     # data same as separator4
        esignature = bytes.fromhex(SMA_ESIGNATURE + "09A0")

        if cmd == "login":
            sep2 = bytes([0x00, 0x01])                                                                  # separator for login
            esignature = bytes.fromhex(SMA_ESIGNATURE + "0EA0")
            encpasswd = [0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88]
            encpasswd[0:len(self.password)] = [((0x88 + ord(char)) & 0xff) for char in self.password]   # encode password
            data = int(time.time()).to_bytes(4, byteorder='little')                                     # timestamp utc
            data += sep4 + bytes(encpasswd) + sep4                                                      # setarator4 + password + setarator4
        elif cmd == "logout":
            sep2 = bytes([0x00, 0x03])                                                                  # separator for logout
            esignature = bytes.fromhex(SMA_ESIGNATURE + "08A0")
            data = bytes([])                                                                            # no data on logout

        msg = bytes.fromhex(SMA_PKT_HEADER) + bytes([0x00, 0x00]) + esignature                          # header + placeholder len + signature
        msg += self.target_id + sep2 + self.my_id + sep2                                                # targets and my address
        msg += sep4 + (self.pkt_id | 0x8000).to_bytes(2, byteorder='little')                            # packet counter
        msg += commands[0].to_bytes(4, byteorder='little')                                              # command + first + last
        msg += commands[1].to_bytes(4, byteorder='little')
        msg += commands[2].to_bytes(4, byteorder='little')
        msg += data                                                                                     # data
        pkt_len = (len(msg)-20).to_bytes(2, byteorder='big')                                            # calculate packet length
        msg = msg[:12] + pkt_len + msg[14:]                                                             # insert packet length

        self.logger.debug("> %s", msg.hex())
        return msg

    def _send_recieve(self, cmd, receive=True):
        repeat = 0
        while repeat < self.retry:
            repeat += 1
            try:
                msg = self._packet(cmd)
                self.sock.sendto(msg, (self.host, self.port))
                if not receive:
                    return
                data, address = self.sock.recvfrom(300)
                self.logger.debug("< %s", data.hex())
                size = len(data)
                if size > 42:
                    pkt_id = unpack_from("H", data, offset=40)[0]
                    error = unpack_from("I", data, offset=36)[0]
                    pkt_id &= 0x7FFF
                    # if (pkt_id != self.pkt_id) or (error != 0):
                    if error != 0:
                        self.logger.debug("Req/Rsp: Packet ID %X/%X, Error %d" % (self.pkt_id, pkt_id, error))
                        raise smaError("Inverter answer does not match our parameters.")
                    if (pkt_id != self.pkt_id):
                        self.pkt_id = pkt_id
                else:
                    raise smaError("Format of inverter response does not fit.")
                return data
            except TimeoutError as e:
                self.logger.error("Timeout")
                # pass
                continue

            raise smaError("No response")

    def _login(self):
        data = self._send_recieve("login")
        if data:
            inv_susyid, inv_serial = unpack_from("<HI", data, offset=28)
            self.serial = inv_serial
            self.target_id = inv_susyid.to_bytes(2, byteorder='little') + inv_serial.to_bytes(4, byteorder='little')
            self.logger.debug("Logged in to inverter susyid: %d, serial: %d" % (inv_susyid, inv_serial))
            return True
        return False

    def _logout(self):
        self._send_recieve("logout", False)
        self.pkt_id = 0
        return True

    def _fetch(self, command):
        data = self._send_recieve(command)
        data_len = len(data)
        sensors = {}

        if data:
            cmd = unpack_from("H", data, offset=55)[0]
            self.logger.debug("Data identifier %02X" % cmd)
            if cmd == 0x821E:
                inv_class = unpack_from("I", data, offset=102)[0] & 0x00FFFFFF
                i = 142
                inv_type = 0
                while (unpack_from("I", data, offset=i)[0] != 0x00FFFFFE) and i < data_len: # 0x00FFFFFE is the end marker for attributes
                    temp = unpack_from("I", data, offset=i)[0]
                    if (temp & 0xFF000000) == 0x01000000: # in some models a catalogue is transmitted, right model marked with: 0x01000000 OR INV_Type
                        inv_type = temp & 0x00FFFFFF
                    i = i + 4
                self.inv_class = str(inv_class)
                self.inv_type = str(inv_type)
                if inv_class in SMA_INV_CLASS:
                    self.inv_class = SMA_INV_CLASS[inv_class]
                if inv_type in SMA_INV_TYPE:
                    self.inv_type = SMA_INV_TYPE[inv_type]

            elif cmd == 0x2377:
              temp = unpack_from("I", data, offset=62)[0]
              value = 0
              if (temp != -0x80000000) and (temp != 0xFFFFFFFF) and (temp != 0x80000000):
                  value = temp / 100.0
              sensors["temp"] = { "value": value, "unit": "°C", "t": "temperature"}

            elif cmd == 0x4657:
              freq = unpack_from("I", data, offset=62)[0]
              value = 0
              if (freq != -0x80000000) and (freq != 0xFFFFFFFF) and (freq != 0x80000000):
                  value = freq / 100.0
              sensors["frequency"] = { "value": value, "unit": "Hz", "t": "frequency"}

            elif cmd == 0x251E:
              pdc1 = unpack_from("I", data, offset=62)[0]
              pdc2 = 0
              if data_len >= 90:
                pdc2 = unpack_from("I", data, offset=90)[0]

              if (pdc2 < 0) or (pdc2 == 0x80000000):
                  pdc2 = 0

              if (pdc1 < 0) or (pdc1 == 0x80000000):
                  pdc1 = 0

              sensors["pdc_string1"] = { "value": pdc1, "unit": "W", "t": "power" }
              sensors["pdc_string2"] = { "value": pdc2, "unit": "W", "t": "power" }

            elif cmd == 0x4640:
              for metric in [
                      ["pac_phase1", unpack_from("I", data, offset=62)[0], "W"],
                      ["pac_phase2", unpack_from("I", data, offset=90)[0], "W"],
                      ["pac_phase3", unpack_from("I", data, offset=118)[0], "W"],
                      ]:
                  value = 0
                  if (metric[1] != -0x80000000) and (metric[1] != 0xFFFFFFFF) and (metric[1] != 0x80000000):
                      value = metric[1]
                  sensors[metric[0]] = {"value": value, "unit": metric[2], "t": "power"} 
                    
            elif cmd == 0x451F:
              udc1 = unpack_from("I", data, offset=62)[0]
              if data_len < 146:
                  udc2 = 0
                  idc1 = unpack_from("I", data, offset=90)[0]
                  idc2 = 0
              else:
                  udc2 = unpack_from("I", data, offset=90)[0]
                  idc1 = unpack_from("I", data, offset=118)[0]
                  idc2 = unpack_from("I", data, offset=146)[0]

              for metric in [
                      ["udc_string1", udc1, "V"],
                      ["udc_string2", udc2, "V"],
                      ["idc_string1", idc1, "A"],
                      ["idc_string2", idc2, "A"],
                      ]:
                  value = 0
                  if (metric[1] != -0x80000000) and (metric[1] != 0xFFFFFFFF) and (metric[1] != 0x80000000):
                      value = metric[1] / 100.0
                  sensors[metric[0]] = {"value": value, "unit": metric[2], "t": "voltage"} 
                  if metric[2] == "A":
                    sensors[metric[0]]["t"] = "current"

            elif cmd == 0x4648:
              for metric in [
                      ["uac_phase1", unpack_from("I", data, offset=62)[0], "V"],
                      ["uac_phase2", unpack_from("I", data, offset=90)[0], "V"],
                      ["uac_phase3", unpack_from("I", data, offset=118)[0], "V"],
                      ["iac_phase1", unpack_from("I", data, offset=146)[0], "A"],
                      ["iac_phase2", unpack_from("I", data, offset=174)[0], "A"],
                      ["iac_phase3", unpack_from("I", data, offset=202)[0], "A"],
                      ]:
                  value = 0
                  if (metric[1] != -0x80000000) and (metric[1] != 0xFFFFFFFF) and (metric[1] != 0x80000000):
                      value = metric[1] / 100.0
                  sensors[metric[0]] = {"value": value, "unit": metric[2], "t": "voltage"} 
                  if metric[2] == "A":
                    sensors[metric[0]]["t"] = "current"

            elif cmd == 0x2601:
                if data_len >= 66:
                    value = unpack_from("I", data, offset=62)[0]
                    if (value != 0x80000000) and (value != 0xFFFFFFFF) and (value > 0):
                        sensors['energy_total'] = { 'value': value / 1000, "unit": "kWh", "t": "energy" }
                if data_len >= 82:
                    value = unpack_from("I", data, offset=78)[0]
                    sensors['energy_today'] = { 'value': value / 1000, "unit": "kWh", "t": "energy" }

            elif cmd == 0x263F:
                value = unpack_from("I", data, offset=62)[0]
                if (value == 0x80000000):
                    value = 0
                sensors['power_ac_total'] = { 'value': value, "unit": "W", "t": "power" }
            return sensors

    def init(self):
        self._login()
        self._fetch("info")
        self._logout()

    def metrics(self):
        self._login()
        data = self._fetch("dc_power") | \
          self._fetch("dc_voltage_current") | \
          self._fetch("ac_voltage_current") | \
          self._fetch("energy") | \
          self._fetch("temp") | \
          self._fetch("freq") | \
          self._fetch("power_ac_total") | \
          self._fetch("ac_power") 
        self._logout()
        return data
    

TOPIC = os.environ["SMA_TOPIC"]
INVERTER_IP = os.environ["SMA_INVERTER_IP"]
INVERTER_PASSWORD = os.environ["SMA_INVERTER_PASSWORD"]
MQTT_HOST = os.environ["SMA_MQTT_HOST"]

SLEEP_INTERVAL=5 #seconds

client = mqtt.Client()
client.connect(MQTT_HOST)
client.loop_start()

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
logging.info(f"Serial: {MY_SERIAL}")

inverter = SMA_SPEEDWIRE(INVERTER_IP, INVERTER_PASSWORD)
inverter.init()

def stat_t(metric_name):
    return f"sma/{INVERTER_IP}/{metric_name}"

for metric_name, data in inverter.metrics().items():
    splitted_ip = INVERTER_IP.split('.')
    hex_inverter_ip = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, splitted_ip))

    topic = f"homeassistant/sensor/speedwire_sma_{hex_inverter_ip}/{metric_name}/config"

    stat_cla = "measurement"
    if data['unit'] == "kWh":
      stat_cla = "total_increasing"

    config = { 
              "name": metric_name, 
              "stat_t": stat_t(metric_name),
              "uniq_id": f"sma_speedwire_{hex_inverter_ip}_{metric_name}",
              "unit_of_meas": data["unit"],
              "dev_cla": data["t"],
              "stat_cla": stat_cla,
              "dev": {"name": f"SMA Inverter {INVERTER_IP}", 
                      "mf": "SMA", 
                      "ids": f"SMA-{hex_inverter_ip}",
                      "mdl": inverter.inv_type},
              "exp_aft": SLEEP_INTERVAL * 2,
             }
    logging.info(f"Creating HA auto discovery messages: {topic}")
    client.publish(topic, payload=json.dumps(config), retain=True)

time.sleep(1)

while True:
    cur = time.monotonic()
    metrics = inverter.metrics()
    for metric_name, data in metrics.items():
        if data["value"] != 0:
          client.publish(stat_t(metric_name), payload=data["value"])

    victron_mqtt_pv = { 
                       "pv": {
                             "power": metrics["power_ac_total"]["value"],
                             "voltage": metrics["uac_phase1"]["value"],
                             "current": metrics["iac_phase1"]["value"] +
                                        metrics["iac_phase2"]["value"] +
                                        metrics["iac_phase3"]["value"],
                             "energy_forward": metrics["energy_today"]["value"],
                             "L1": {
                                   "power":   metrics["pac_phase1"]["value"],
                                   "voltage": metrics["uac_phase1"]["value"],
                                   "current": metrics["iac_phase1"]["value"],
                             },
                             "L2": {
                                   "power":   metrics["pac_phase2"]["value"],
                                   "voltage": metrics["uac_phase2"]["value"],
                                   "current": metrics["iac_phase2"]["value"],
                             },
                             "L3": {
                                   "power":   metrics["pac_phase3"]["value"],
                                   "voltage": metrics["uac_phase3"]["value"],
                                   "current": metrics["iac_phase3"]["value"],
                             },
                           }, 
                      }
    client.publish(TOPIC, payload=json.dumps(victron_mqtt_pv))
    duration = (time.monotonic() - cur)
    logging.info(f"Metric publish took {duration} seconds")
    time.sleep(SLEEP_INTERVAL - duration)

