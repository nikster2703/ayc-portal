"""
AYC Portal — Flask extension singletons.
Instantiated here without an app; bound to the app via init_app() in app.py.
Blueprints import from here so @csrf.exempt works at decoration time.
"""

from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
