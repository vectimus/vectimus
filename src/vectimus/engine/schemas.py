"""Cedar entity and action schema definitions for Vectimus.

Defines the Cedar schema as a Python string constant.  The evaluator passes
this schema to cedarpy so that policies can reference well-typed entities,
actions and context attributes.
"""

# Cedar schema expressed in the JSON format that cedarpy accepts.
# This mirrors the entity model used by Vectimus policies.
CEDAR_SCHEMA_JSON: dict = {
    "Vectimus": {
        "entityTypes": {
            "User": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "persona": {"type": "String", "required": False},
                        "groups": {
                            "type": "Set",
                            "element": {"type": "String"},
                            "required": False,
                        },
                    },
                },
            },
            "Agent": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "persona": {"type": "String", "required": False},
                        "groups": {
                            "type": "Set",
                            "element": {"type": "String"},
                            "required": False,
                        },
                    },
                },
            },
            "Tool": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "name": {"type": "String", "required": False},
                    },
                },
            },
        },
        "actions": {
            "shell_command": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "file_path": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "file_write": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "file_path": {"type": "String", "required": False},
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "file_read": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "file_path": {"type": "String", "required": False},
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "web_request": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "url": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "mcp_tool": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "mcp_server": {"type": "String", "required": False},
                            "mcp_tool": {"type": "String", "required": False},
                            "command": {"type": "String", "required": False},
                            "file_path": {"type": "String", "required": False},
                            "url": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "package_operation": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "package_name": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "git_operation": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "infrastructure": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "agent_spawn": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
            "agent_message": {
                "appliesTo": {
                    "principalTypes": ["User", "Agent"],
                    "resourceTypes": ["Tool"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "command": {"type": "String", "required": False},
                            "cwd": {"type": "String", "required": False},
                        },
                    },
                },
            },
        },
    },
}
