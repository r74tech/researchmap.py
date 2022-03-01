researchmap package
===================

Submodules
----------

researchmap.adapter module
--------------------------

.. automodule:: researchmap.adapter
   :members:
   :undoc-members:
   :show-inheritance:

researchmap.errors module
-------------------------

.. automodule:: researchmap.errors
   :members:
   :undoc-members:
   :show-inheritance:

researchmap.wrapper module
--------------------------

.. automodule:: researchmap.wrapper
   :members:
   :undoc-members:
   :show-inheritance:

Module contents
---------------

.. automodule:: researchmap
   :members:
   :undoc-members:
   :show-inheritance:



API Reference
---------------

.. attributetable:: researchmap.adapter

.. autoclass:: researchmap.adapter.Auth()
    :members:
    :exclude-members: get_usage

    .. automethod:: Auth.gen_jwt()
        :decorator:

    .. automethod:: Auth.gen_pubkey()
        :decorator:

    .. automethod:: Auth.is_authorization()
        :decorator:

    .. automethod:: Auth.get_access_token()
        :decorator:
