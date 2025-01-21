"""Route map model."""
from functools import cached_property
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, Field, model_validator


class RouteMapEntry(BaseModel):
    """Route Map Entry model.
    
    Attributes:
        sequence: Entry sequence number
        action: Entry action (permit/deny)
        match_conditions: Dictionary of match conditions
            Format: {
                'as-path': str | List[str],
                'community': str | List[str],
                'ip': {
                    'address': str | List[str],
                    'next-hop': str | List[str],
                    'prefix-list': str | List[str]
                },
                'tag': str | List[str],
                ...
            }
        set_actions: Dictionary of set actions
            Format: {
                'as-path': {'prepend': str | List[str]},
                'community': str | List[str],
                'local-preference': str,
                'metric': str,
                'origin': str,
                'tag': str,
                ...
            }
    """

    sequence: int
    action: str
    match_conditions: Dict[str, Any] = Field(default_factory=dict)
    set_actions: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode='before')
    @classmethod
    def handle_legacy_format(cls, data: Any) -> Any:
        """Handle legacy format with 'match' and 'set' keys."""
        if isinstance(data, dict):
            # Convert match/set keys to match_conditions/set_actions
            if 'match' in data:
                data['match_conditions'] = data.pop('match')
            if 'set' in data:
                data['set_actions'] = data.pop('set')
        return data

    @cached_property
    def match(self) -> Dict[str, Any]:
        """Return match conditions for backward compatibility."""
        return self.match_conditions

    @cached_property
    def set(self) -> Dict[str, Any]:
        """Return set actions for backward compatibility."""
        return self.set_actions

    def add_match_condition(self, condition_type: str, value: Union[str, List[str], Dict[str, Any]]) -> None:
        """Add a match condition."""
        if condition_type in self.match_conditions:
            if isinstance(self.match_conditions[condition_type], list):
                if isinstance(value, list):
                    self.match_conditions[condition_type].extend(value)
                else:
                    self.match_conditions[condition_type].append(value)
            elif isinstance(self.match_conditions[condition_type], dict):
                if isinstance(value, dict):
                    self.match_conditions[condition_type].update(value)
            else:
                self.match_conditions[condition_type] = [self.match_conditions[condition_type], value]
        else:
            self.match_conditions[condition_type] = value

    def add_set_action(self, action_type: str, value: Union[str, List[str], Dict[str, Any]]) -> None:
        """Add a set action."""
        if action_type in self.set_actions:
            if isinstance(self.set_actions[action_type], list):
                if isinstance(value, list):
                    self.set_actions[action_type].extend(value)
                else:
                    self.set_actions[action_type].append(value)
            elif isinstance(self.set_actions[action_type], dict):
                if isinstance(value, dict):
                    self.set_actions[action_type].update(value)
            else:
                self.set_actions[action_type] = [self.set_actions[action_type], value]
        else:
            self.set_actions[action_type] = value


class RouteMap(BaseModel):
    """Route map model."""

    name: str
    description: Optional[str] = None
    entries: Dict[str, RouteMapEntry] = Field(default_factory=dict)

    def __init__(self, name: str, entries: Optional[List[RouteMapEntry]] = None, **data):
        """Initialize route map."""
        entries_dict = {}
        if entries:
            for entry in entries:
                entries_dict[entry.sequence] = entry
        super().__init__(name=name, entries=entries_dict, **data)

    @cached_property
    def entries_list(self) -> List[RouteMapEntry]:
        """Return entries as a sorted list."""
        return sorted(self.entries.values(), key=lambda x: x.sequence)

    def add_entry(self, entry: Union[RouteMapEntry, dict]) -> None:
        """Add an entry to the route map."""
        if isinstance(entry, dict):
            if 'sequence' not in entry:
                entry['sequence'] = max(self.entries.keys(), default=0) + 10
            entry = RouteMapEntry(**entry)
        self.entries[entry.sequence] = entry

    def remove_entry(self, sequence: int) -> None:
        """Remove an entry from the route map."""
        if sequence in self.entries:
            del self.entries[sequence]

    def get_entry(self, sequence: int) -> Optional[RouteMapEntry]:
        """Get an entry by sequence number."""
        return self.entries.get(sequence)

    def __getitem__(self, key: Union[str, int]) -> Union[str, RouteMapEntry, Dict[int, RouteMapEntry]]:
        """Get item by key."""
        if isinstance(key, int):
            return self.entries[key]
        if key == "entries":
            return self.entries
        return getattr(self, key)

    def __len__(self) -> int:
        """Return number of entries."""
        return len(self.entries)

    def __contains__(self, sequence: int) -> bool:
        """Check if sequence number exists."""
        return sequence in self.entries
