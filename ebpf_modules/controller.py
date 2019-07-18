class Controller:
    """ Super simple message passing mechanism to control threads. When
        any thread (including main one) is interrupted by a signal or exception
        it sets stopped=True and thereby cause all other threads to finish.
    """

    def __init__(self):
        self.stopped = False

