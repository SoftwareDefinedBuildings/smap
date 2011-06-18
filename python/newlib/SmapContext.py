
class SmapContext:
    def __init__(self, timezone):
        self.timezone = timezone

    def http_get(self, request, resource, query=None):
        return {
            'LocalTimezone' : self.timezone
            }
