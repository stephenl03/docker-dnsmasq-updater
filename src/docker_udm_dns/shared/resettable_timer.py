from threading import Timer


class ResettableTimer():
    """
    A resettable timer class.

    A timer class so we can delay writes to the external device
    to allow for multiple Docker events in a short space of time
    without hammering the device.
    """

    def __init__(self, delay, function):
        """Initialize timing."""
        self._running = False
        self._delay = delay
        self._function = function
        self._timer = Timer(self._delay, self._function)

    def __set(self):
        self._timer = Timer(self._delay, self._function)

    def start(self):
        """If not running, start timer."""
        if not self._running:
            self.__set()
            self._timer.daemon = True
            self._timer.start()
            self._running = True

    def cancel(self):
        """If running, cancel timer."""
        if self._running:
            self._timer.cancel()
            self._running = False

    def reset(self):
        """Reset timer."""
        self.cancel()
        self.start()