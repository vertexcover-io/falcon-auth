# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division

import datetime
import json


class ExtendedJSONEncoder(json.JSONEncoder):
    """
    A JSON encoder that allows for more common Python data types.

    In addition to the defaults handled by ``json``, this also supports:

        * ``datetime.datetime``
        * ``datetime.date``
        * ``datetime.time``
    """
    def default(self, data):
        if isinstance(data, (datetime.datetime, datetime.date, datetime.time)):
            return data.isoformat('T')
        else:
            return super(ExtendedJSONEncoder, self).default(data)
