"""
Services package.

Houses business-logic service modules that sit between the API layer
and the persistence/ML layers (e.g. Sysmon log parsing). Each module
here should remain free of FastAPI route definitions and of direct
MongoDB query logic — those belong in `app/api/` and
`app/db/repositories/` respectively.
"""