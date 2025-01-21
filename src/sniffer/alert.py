from dataclasses import dataclass


@dataclass
class AlertSystem:
    warnings = {}
    threats = {}
    closed = {}
    
    
