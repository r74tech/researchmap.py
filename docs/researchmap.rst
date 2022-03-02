.. currentmodule:: researchmap

API Reference
===============

Adapter
-------

Auth
~~~~

.. attributetable:: researchmap.adapter.Auth

.. autoclass:: researchmap.adapter.Auth
    :members:
    :inherited-members:

RequestsAdapter
~~~~~~~~~~~~~~~~~~

.. attributetable:: researchmap.adapter.RequestsAdapter

.. autoclass:: researchmap.adapter.RequestsAdapter
    :members:
    :inherited-members:


Exceptions
------------

The following exceptions are thrown by the library.

.. autoexception:: researchmap.errors.HTTPException
    :members:
    :inherited-members:

.. autoexception:: researchmap.errors.UnsupportedResponseType

.. autoexception:: researchmap.errors.UnauthorizedClient

.. autoexception:: researchmap.errors.AccessDenied

.. autoexception:: researchmap.errors.InvalidClient

.. autoexception:: researchmap.errors.InvalidScope

.. autoexception:: researchmap.errors.InvalidGrant

.. autoexception:: researchmap.errors.UnsupportedGrantType

.. autoexception:: researchmap.errors.InvalidVersion

.. autoexception:: researchmap.errors.ParseError

.. autoexception:: researchmap.errors.InvalidNonce

.. autoexception:: researchmap.errors.InvalidRequest

.. autoexception:: researchmap.errors.InvalidToken

.. autoexception:: researchmap.errors.MalformedToken

.. autoexception:: researchmap.errors.InsufficientScope

.. autoexception:: researchmap.errors.InvalidIP

.. autoexception:: researchmap.errors.Forbidden

.. autoexception:: researchmap.errors.NotFound

.. autoexception:: researchmap.errors.MethodNotAllowed

.. autoexception:: researchmap.errors.MaxSearchResult

.. autoexception:: researchmap.errors.DatabaseError

.. autoexception:: researchmap.errors.ServerError

.. autoexception:: researchmap.errors.InternalServerError




Exception Hierarchy
~~~~~~~~~~~~~~~~~~~~~

.. exception_hierarchy::

    - :exc:`Exception`
        - :exc:`ResearchmapException`
            - :exc:`HTTPException`
                - :exc:`UnsupportedResponseType`
                - :exc:`UnauthorizedClient`
                - :exc:`AccessDenied`
                - :exc:`InvalidClient`
                - :exc:`InvalidScope`
                - :exc:`InvalidGrant`
                - :exc:`UnsupportedGrantType`
                - :exc:`InvalidVersion`
                - :exc:`ParseError`
                - :exc:`InvalidNonce`
                - :exc:`InvalidRequest`
                - :exc:`InvalidToken`
                - :exc:`MalformedToken`
                - :exc:`InsufficientScope`
                - :exc:`InvalidIP`
                - :exc:`Forbidden`
                - :exc:`NotFound`
                - :exc:`MethodNotAllowed`
                - :exc:`MaxSearchResult`
                - :exc:`DatabaseError`
                - :exc:`ServerError`
                - :exc:`InternalServerError`