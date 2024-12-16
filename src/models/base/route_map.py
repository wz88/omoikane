from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class RouteMapEntry(BaseModel):
    """Base model for route-map entry configuration."""
    sequence: int
    action: str  # permit/deny
    description: Optional[str] = None
    match_conditions: Dict[str, List[str]] = Field(default_factory=dict)
    set_actions: Dict[str, List[str]] = Field(default_factory=dict)
    match_statements: Dict[str, List[str]] = Field(default_factory=dict)  # For backward compatibility
    set_statements: Dict[str, List[str]] = Field(default_factory=dict)  # For backward compatibility

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        if key == 'match_statements':
            return self.match_conditions
        elif key == 'set_statements':
            return self.set_actions
        return getattr(self, key)


class RouteMap(BaseModel):
    """Base model for route-map configuration."""
    name: str
    entries: List[RouteMapEntry] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
