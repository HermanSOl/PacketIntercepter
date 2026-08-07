from __future__ import annotations
from abc import ABC, abstractmethod
from collections import deque
from typing import TYPE_CHECKING
import threading

if TYPE_CHECKING:
    from pkt_capture_parse import Packet

class DetectionRule:
    @abstractmethod
    def __init__(self, condition: bool):
        self.condition = condition

    @abstractmethod
    def check(self,pkt: Packet):
        True if self.condition else False


class SusAlert:
    def __init__(self):
        pass



class AlertHandler():

    def __init__(self, maxlen: int = 500):
        self.lock = threading.Lock()
        self.alerts: deque[SusAlert] = deque(maxlen=maxlen)


    def process_alert(self, alert: SusAlert):
        with self.lock:
            self.alerts.append(alert)

    def get_alerts(self) -> list[SusAlert]:
        with self.lock:
            return list(self.alerts)