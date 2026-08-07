from abc import ABC, abstractmethod

class DetectionRule:
    @abstractmethod
    def __init__(self, condition: bool):
        self.condition = condition

    @abstractmethod
    def process_condition(self):
        True if self.condition else False


class SusAlert:
    def __init__(self):
        pass


def process_alerts(alerts: list[SusAlert]):
    ### some implementation in the future
    return